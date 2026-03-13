/************************************************************************
 *   IRC - Internet Relay Chat, src/websocket.c
 *   Copyright (C) 2026 Bahamut development team
 *
 *   WebSocket transport (RFC 6455) for browser-based IRC clients.
 *   Implements the "irc" subprotocol per IRCv3 WebSocket spec.
 *
 *   Layering: SSL(WebSocket(IRC)) — each layer wraps the next.
 *   WS handshake happens after any SSL handshake completes.
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "sbuf.h"
#include "websocket.h"
#include "base64.h"

#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

/* RFC 6455 magic GUID for Sec-WebSocket-Accept */
#define WS_MAGIC_GUID "258EAFA5-E914-47DA-95CA-5AB5DC085B6A"

/* Max HTTP handshake size (headers only) */
#define WS_MAX_HANDSHAKE  4096

/* Max WebSocket payload we'll accept (16 KB — IRC messages are ≤512 bytes) */
#define WS_MAX_PAYLOAD    16384

/* WS opcodes */
#define WS_OP_CONTINUATION  0x0
#define WS_OP_TEXT          0x1
#define WS_OP_BINARY        0x2
#define WS_OP_CLOSE         0x8
#define WS_OP_PING          0x9
#define WS_OP_PONG          0xA

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

WSState *
ws_state_alloc(void)
{
    WSState *ws = (WSState *)MyMalloc(sizeof(WSState));
    memset(ws, 0, sizeof(WSState));
    return ws;
}

void
ws_state_free(WSState *ws)
{
    if (!ws)
        return;
    if (ws->hs_buf)
        MyFree(ws->hs_buf);
    MyFree(ws);
}

/* ------------------------------------------------------------------ */
/* Static helpers                                                     */
/* ------------------------------------------------------------------ */

/*
 * Case-insensitive header value search.
 * Returns pointer into haystack after ": " if header found, else NULL.
 */
static const char *
ws_get_header(const char *headers, const char *name)
{
    const char *p = headers;
    int nlen = strlen(name);

    while (*p)
    {
        /* Match header name case-insensitively at start of line */
        if (strncasecmp((char *)p, (char *)name, nlen) == 0 && p[nlen] == ':')
        {
            p += nlen + 1;
            while (*p == ' ' || *p == '\t')
                p++;
            return p;
        }
        /* Skip to next line */
        while (*p && *p != '\n')
            p++;
        if (*p == '\n')
            p++;
    }
    return NULL;
}

/*
 * Extract a header value up to \r or \n into a NUL-terminated buffer.
 * Returns length of value.
 */
static int
ws_copy_header_value(const char *start, char *out, int outmax)
{
    int i = 0;
    while (start[i] && start[i] != '\r' && start[i] != '\n' && i < outmax - 1)
    {
        out[i] = start[i];
        i++;
    }
    out[i] = '\0';
    return i;
}

/*
 * Case-insensitive check whether comma-separated header value contains token.
 */
static int
ws_header_contains(const char *hdr_start, const char *token)
{
    char buf[256];
    char *p, *save = NULL;
    int tlen = strlen(token);

    ws_copy_header_value(hdr_start, buf, sizeof(buf));

    for (p = buf; ; p = NULL)
    {
        char *tok;
        if (p)
        {
            tok = p;
            /* Find next comma */
            save = strchr(tok, ',');
            if (save)
                *save++ = '\0';
        }
        else if (save)
        {
            tok = save;
            save = strchr(tok, ',');
            if (save)
                *save++ = '\0';
        }
        else
            break;

        /* Trim leading whitespace */
        while (*tok == ' ' || *tok == '\t')
            tok++;
        /* Trim trailing whitespace */
        {
            int len = strlen(tok);
            while (len > 0 && (tok[len-1] == ' ' || tok[len-1] == '\t'))
                tok[--len] = '\0';
        }
        if (strncasecmp(tok, (char *)token, tlen) == 0 && tok[tlen] == '\0')
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Handshake                                                          */
/* ------------------------------------------------------------------ */

/*
 * Send a raw HTTP response bypassing IRC framing.
 * Uses sbuf_put to the sendQ and calls send_queued.
 */
static void
ws_send_raw(aClient *cptr, const char *data, int len)
{
    if (sbuf_put(&cptr->sendQ, data, len) >= 0)
        send_queued(cptr);
}

/*
 * Process accumulated HTTP upgrade request.
 * Returns number of unconsumed bytes (data after \r\n\r\n is first WS frame),
 * or -1 on failure.
 */
static int
ws_do_handshake(aClient *cptr, WSState *ws)
{
    char *end_of_headers;
    char key_buf[128];
    char concat[256];
    unsigned char sha1_hash[EVP_MAX_MD_SIZE];
    unsigned int sha1_len;
    char accept_b64[64];
    char response[512];
    int resp_len;
    int unconsumed;
    const char *hdr;
    const char *bad_req = "HTTP/1.1 400 Bad Request\r\n\r\n";

    /* NUL-terminate for string operations */
    ws->hs_buf[ws->hs_len] = '\0';

    /* Find end of headers */
    end_of_headers = strstr(ws->hs_buf, "\r\n\r\n");
    if (!end_of_headers)
        return -1; /* shouldn't happen — caller checks */

    unconsumed = ws->hs_len - (int)(end_of_headers - ws->hs_buf + 4);

    /* Verify it starts with GET */
    if (strncmp(ws->hs_buf, "GET ", 4) != 0)
    {
        ws_send_raw(cptr, bad_req, strlen(bad_req));
        return -1;
    }

    /* Check Upgrade: websocket */
    hdr = ws_get_header(ws->hs_buf, "Upgrade");
    if (!hdr || !ws_header_contains(hdr, "websocket"))
    {
        ws_send_raw(cptr, bad_req, strlen(bad_req));
        return -1;
    }

    /* Check Connection: Upgrade */
    hdr = ws_get_header(ws->hs_buf, "Connection");
    if (!hdr || !ws_header_contains(hdr, "Upgrade"))
    {
        ws_send_raw(cptr, bad_req, strlen(bad_req));
        return -1;
    }

    /* Check Sec-WebSocket-Version: 13 */
    hdr = ws_get_header(ws->hs_buf, "Sec-WebSocket-Version");
    if (!hdr || strncmp(hdr, "13", 2) != 0)
    {
        const char *ver_resp =
            "HTTP/1.1 426 Upgrade Required\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n";
        ws_send_raw(cptr, ver_resp, strlen(ver_resp));
        return -1;
    }

    /* Check Sec-WebSocket-Protocol contains "irc" (optional but recommended) */
    hdr = ws_get_header(ws->hs_buf, "Sec-WebSocket-Protocol");
    /* We accept connections even without the subprotocol header —
     * many web clients don't send it */

    /* Extract Sec-WebSocket-Key */
    hdr = ws_get_header(ws->hs_buf, "Sec-WebSocket-Key");
    if (!hdr)
    {
        ws_send_raw(cptr, bad_req, strlen(bad_req));
        return -1;
    }
    ws_copy_header_value(hdr, key_buf, sizeof(key_buf));

    /* Compute Sec-WebSocket-Accept: SHA1(key + GUID) → base64 */
    snprintf(concat, sizeof(concat), "%s%s", key_buf, WS_MAGIC_GUID);
    if (!EVP_Digest(concat, strlen(concat), sha1_hash, &sha1_len,
                    EVP_sha1(), NULL))
    {
        ws_send_raw(cptr, bad_req, strlen(bad_req));
        return -1;
    }
    base64_encode(sha1_hash, (int)sha1_len, accept_b64, sizeof(accept_b64));

    /* Build 101 Switching Protocols response */
    if (hdr && ws_get_header(ws->hs_buf, "Sec-WebSocket-Protocol") &&
        ws_header_contains(ws_get_header(ws->hs_buf, "Sec-WebSocket-Protocol"), "irc"))
    {
        resp_len = snprintf(response, sizeof(response),
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n"
            "Sec-WebSocket-Protocol: irc\r\n"
            "\r\n", accept_b64);
    }
    else
    {
        resp_len = snprintf(response, sizeof(response),
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            "Sec-WebSocket-Accept: %s\r\n"
            "\r\n", accept_b64);
    }

    ws_send_raw(cptr, response, resp_len);

    /* Transition to active WebSocket mode */
    SetWebSocket(cptr);
    ClearPendWS(cptr);

    /* Free handshake buffer — no longer needed */
    MyFree(ws->hs_buf);
    ws->hs_buf = NULL;
    ws->hs_len = 0;

    /* Reset frame parser state */
    ws->frame_hdr_len = 0;
    ws->frame_hdr_need = 2; /* minimum header: opcode + len byte */
    ws->payload_len = 0;
    ws->payload_pos = 0;

    return unconsumed;
}

/* ------------------------------------------------------------------ */
/* Frame writer (server→client, no mask)                              */
/* ------------------------------------------------------------------ */

int
ws_frame_message(const char *msg, int len, char *outbuf)
{
    int pos = 0;

    /* Byte 0: FIN=1, opcode=TEXT */
    outbuf[pos++] = (char)0x81;

    /* Byte 1+: payload length (server→client: MASK bit = 0) */
    if (len <= 125)
    {
        outbuf[pos++] = (char)len;
    }
    else if (len <= 65535)
    {
        outbuf[pos++] = (char)126;
        outbuf[pos++] = (char)((len >> 8) & 0xFF);
        outbuf[pos++] = (char)(len & 0xFF);
    }
    else
    {
        /* >64KB IRC messages don't exist, but handle gracefully */
        outbuf[pos++] = (char)127;
        outbuf[pos++] = 0; outbuf[pos++] = 0;
        outbuf[pos++] = 0; outbuf[pos++] = 0;
        outbuf[pos++] = (char)((len >> 24) & 0xFF);
        outbuf[pos++] = (char)((len >> 16) & 0xFF);
        outbuf[pos++] = (char)((len >> 8) & 0xFF);
        outbuf[pos++] = (char)(len & 0xFF);
    }

    /* Payload: raw IRC message, no \r\n per IRCv3 WS spec */
    memcpy(outbuf + pos, msg, len);
    pos += len;

    return pos;
}

/* ------------------------------------------------------------------ */
/* Control frames                                                     */
/* ------------------------------------------------------------------ */

void
ws_send_close(aClient *cptr, int code, const char *reason)
{
    char buf[128 + 14]; /* max control payload is 125 */
    int plen = 0;
    int flen;
    char frame[128 + 14];

    if (code > 0)
    {
        buf[plen++] = (char)((code >> 8) & 0xFF);
        buf[plen++] = (char)(code & 0xFF);
        if (reason)
        {
            int rlen = strlen(reason);
            if (rlen > 123)
                rlen = 123; /* control frame payload max 125: 2 for code */
            memcpy(buf + plen, reason, rlen);
            plen += rlen;
        }
    }

    /* Frame: FIN=1, opcode=CLOSE */
    frame[0] = (char)0x88;
    frame[1] = (char)plen;
    if (plen > 0)
        memcpy(frame + 2, buf, plen);
    flen = 2 + plen;

    sbuf_put(&cptr->sendQ, frame, flen);
    send_queued(cptr);
}

void
ws_send_pong(aClient *cptr, const char *data, int len)
{
    char frame[131]; /* 2 header + 125 max payload */

    if (len > 125)
        len = 125;

    frame[0] = (char)0x8A; /* FIN=1, opcode=PONG */
    frame[1] = (char)len;
    if (len > 0)
        memcpy(frame + 2, data, len);

    sbuf_put(&cptr->sendQ, frame, 2 + len);
    send_queued(cptr);
}

/* ------------------------------------------------------------------ */
/* Frame parser (client→server, masked)                               */
/* ------------------------------------------------------------------ */

/*
 * ws_process_recv — entry point from read_packet().
 *
 * Returns:
 *   >0  success (data queued to recvQ)
 *    0  clean close (WS close frame received)
 *   -1  error (bad frame, protocol violation)
 */
int
ws_process_recv(aClient *cptr, char *buf, int len)
{
    WSState *ws = (WSState *)cptr->ws_state;
    int pos = 0;

    if (!ws)
        return -1;

    /* ---- Handshake phase ---- */
    if (IsPendWS(cptr))
    {
        int need, avail, result;

        /* Allocate handshake buffer on first data */
        if (!ws->hs_buf)
        {
            ws->hs_buf = (char *)MyMalloc(WS_MAX_HANDSHAKE + 1);
            ws->hs_len = 0;
        }

        /* Accumulate data */
        avail = WS_MAX_HANDSHAKE - ws->hs_len;
        need = (len < avail) ? len : avail;
        memcpy(ws->hs_buf + ws->hs_len, buf, need);
        ws->hs_len += need;

        /* Check for end of headers */
        ws->hs_buf[ws->hs_len] = '\0';
        if (!strstr(ws->hs_buf, "\r\n\r\n"))
        {
            if (ws->hs_len >= WS_MAX_HANDSHAKE)
                return -1; /* headers too large */
            return 1; /* need more data */
        }

        result = ws_do_handshake(cptr, ws);
        if (result < 0)
            return -1;

        /* Any data after \r\n\r\n is the start of WS frames */
        if (result > 0)
        {
            pos = len - result;
            /* Fall through to frame processing */
        }
        else
        {
            return 1; /* handshake complete, no trailing data */
        }
    }

    /* ---- Frame processing loop ---- */
    while (pos < len)
    {
        /* Phase 1: Accumulate frame header */
        if (ws->frame_hdr_len < ws->frame_hdr_need)
        {
            while (pos < len && ws->frame_hdr_len < ws->frame_hdr_need)
            {
                ws->frame_hdr[ws->frame_hdr_len++] = (unsigned char)buf[pos++];

                /* After byte 0: check RSV bits */
                if (ws->frame_hdr_len == 1)
                {
                    if (ws->frame_hdr[0] & 0x70) /* RSV1-3 must be 0 */
                        return -1;
                }

                /* After byte 1: determine full header length */
                if (ws->frame_hdr_len == 2)
                {
                    unsigned char b1 = ws->frame_hdr[1];
                    int base_len = b1 & 0x7F;
                    int mask_bit = (b1 >> 7) & 1;

                    if (!mask_bit) /* client→server MUST be masked */
                        return -1;

                    if (base_len <= 125)
                        ws->frame_hdr_need = 2 + 4; /* + mask key */
                    else if (base_len == 126)
                        ws->frame_hdr_need = 2 + 2 + 4; /* + ext16 + mask */
                    else /* 127 */
                        ws->frame_hdr_need = 2 + 8 + 4; /* + ext64 + mask */
                }
            }

            /* Still need more header bytes? */
            if (ws->frame_hdr_len < ws->frame_hdr_need)
                return 1;

            /* Parse complete header */
            ws->fin = (ws->frame_hdr[0] >> 7) & 1;
            ws->opcode = ws->frame_hdr[0] & 0x0F;

            {
                unsigned char b1 = ws->frame_hdr[1];
                int base_len = b1 & 0x7F;
                int mask_offset;

                if (base_len <= 125)
                {
                    ws->payload_len = base_len;
                    mask_offset = 2;
                }
                else if (base_len == 126)
                {
                    ws->payload_len = ((int)ws->frame_hdr[2] << 8) |
                                       (int)ws->frame_hdr[3];
                    mask_offset = 4;
                }
                else /* 127 */
                {
                    /* Only support up to 32-bit lengths (plenty for IRC) */
                    if (ws->frame_hdr[2] || ws->frame_hdr[3] ||
                        ws->frame_hdr[4] || ws->frame_hdr[5])
                        return -1; /* way too large */
                    ws->payload_len = ((int)ws->frame_hdr[6] << 24) |
                                      ((int)ws->frame_hdr[7] << 16) |
                                      ((int)ws->frame_hdr[8] << 8) |
                                       (int)ws->frame_hdr[9];
                    mask_offset = 10;
                }

                if (ws->payload_len > WS_MAX_PAYLOAD)
                    return -1;

                memcpy(ws->mask_key, ws->frame_hdr + mask_offset, 4);
            }

            ws->payload_pos = 0;
        }

        /* Phase 2: Process payload */
        {
            int remaining = ws->payload_len - ws->payload_pos;
            int chunk = (len - pos < remaining) ? (len - pos) : remaining;
            int i;

            /* Unmask in-place */
            for (i = 0; i < chunk; i++)
                buf[pos + i] ^= ws->mask_key[(ws->payload_pos + i) & 3];

            switch (ws->opcode)
            {
                case WS_OP_TEXT:
                {
                    /* Queue unmasked payload to recvQ */
                    if (sbuf_put(&cptr->recvQ, buf + pos, chunk) < 0)
                        return -1;

                    ws->payload_pos += chunk;
                    pos += chunk;

                    /* Complete frame? Append \r\n so the IRC parser sees a line */
                    if (ws->payload_pos >= ws->payload_len)
                    {
                        if (sbuf_put(&cptr->recvQ, "\r\n", 2) < 0)
                            return -1;
                    }
                    break;
                }

                case WS_OP_PING:
                {
                    /* Accumulate ping payload and respond when complete */
                    static char ping_buf[128];

                    if (chunk > 0 && ws->payload_pos + chunk <= (int)sizeof(ping_buf))
                        memcpy(ping_buf + ws->payload_pos, buf + pos, chunk);

                    ws->payload_pos += chunk;
                    pos += chunk;

                    if (ws->payload_pos >= ws->payload_len)
                        ws_send_pong(cptr, ping_buf,
                                     (ws->payload_len <= (int)sizeof(ping_buf))
                                     ? ws->payload_len : 0);
                    break;
                }

                case WS_OP_PONG:
                    /* Discard */
                    ws->payload_pos += chunk;
                    pos += chunk;
                    break;

                case WS_OP_CLOSE:
                {
                    /* Echo close frame back */
                    int code = 1000;
                    if (ws->payload_len >= 2)
                    {
                        code = ((unsigned char)buf[pos] << 8) |
                                (unsigned char)buf[pos + 1];
                    }
                    ws_send_close(cptr, code, NULL);
                    return 0; /* clean close */
                }

                case WS_OP_BINARY:
                    /* Binary frames not supported for IRC */
                    ws_send_close(cptr, 1003, "Binary not supported");
                    return 0;

                default:
                    /* Unknown opcode */
                    return -1;
            }

            /* If frame is complete, reset for next frame */
            if (ws->payload_pos >= ws->payload_len)
            {
                ws->frame_hdr_len = 0;
                ws->frame_hdr_need = 2;
                ws->payload_len = 0;
                ws->payload_pos = 0;
            }
        }
    }

    return 1;
}
