/************************************************************************
 *   IRC - Internet Relay Chat, include/websocket.h
 *   Copyright (C) 2026 Bahamut development team
 *
 *   WebSocket transport for IRCv3 browser clients.
 *   RFC 6455 framing with the IRCv3 subprotocols "text.ircv3.net" and
 *   "binary.ircv3.net" (legacy "irc" is accepted as an alias for text).
 */

#ifndef WEBSOCKET_H
#define WEBSOCKET_H

/*
 * Frame-buffer sizing (shared by send.c's ws_outbuf and websocket.c's scrub
 * buffer so they can't drift apart).
 *
 * WS_MAX_IRC_MSG is the largest IRC message that can reach ws_frame_message()
 * via send_message().  The biggest feeder buffer in send.c is tagbuf[2560]
 * (sendto_one_tags); if a larger one is ever added, bump this to match.
 *
 * A text frame's payload can grow up to 3x when invalid bytes are scrubbed to
 * the 3-byte U+FFFD, so the frame buffer must hold 3x plus the frame header.
 */
#define WS_MAX_IRC_MSG    2560
#define WS_FRAME_BUFSIZE  (3 * WS_MAX_IRC_MSG + 16)

/* Per-client WebSocket state, allocated only for WS connections */
typedef struct WSState {
    /* Handshake accumulation (freed after upgrade) */
    char   *hs_buf;
    int     hs_len;

    /* Negotiated subprotocol: 0 = text (text.ircv3.net / irc), 1 = binary
     * (binary.ircv3.net).  Governs the OUTPUT frame opcode and whether
     * outbound payloads are UTF-8 scrubbed (text) or passed raw (binary). */
    int     binary;

    /* Frame parser state for partial reads */
    unsigned char  frame_hdr[14];   /* max: 2 + 8(ext len) + 4(mask) */
    int            frame_hdr_len;
    int            frame_hdr_need;  /* total header bytes needed */
    int            payload_len;     /* total payload for current frame */
    int            payload_pos;     /* bytes consumed so far */
    unsigned char  mask_key[4];
    unsigned char  opcode;
    unsigned char  fin;
} WSState;

/* Lifecycle */
WSState *ws_state_alloc(void);
void     ws_state_free(WSState *ws);

/* I/O integration — called from s_bsd.c read_packet() */
int  ws_process_recv(aClient *cptr, char *buf, int len);

/* Framing — called from send.c send_message().
 * Writes a single WS data frame for `msg`/`len` into `outbuf` (capacity
 * `outcap`).  `binary` selects the opcode (0x82 binary / 0x81 text); text
 * frames are UTF-8 scrubbed and the whole frame is bounded to `outcap`.
 * Returns the framed length. */
int  ws_frame_message(const char *msg, int len, char *outbuf, int outcap,
                      int binary);

/* Returns 1 if the client negotiated the binary subprotocol, else 0. */
int  ws_is_binary(aClient *cptr);

/* Control frames */
void ws_send_close(aClient *cptr, int code, const char *reason);
void ws_send_pong(aClient *cptr, const char *data, int len);

#endif /* WEBSOCKET_H */
