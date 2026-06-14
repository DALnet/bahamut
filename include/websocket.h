/************************************************************************
 *   IRC - Internet Relay Chat, include/websocket.h
 *   Copyright (C) 2026 Bahamut development team
 *
 *   WebSocket transport for IRCv3 browser clients.
 *   RFC 6455 framing with the "irc" subprotocol.
 */

#ifndef WEBSOCKET_H
#define WEBSOCKET_H

/* Per-client WebSocket state, allocated only for WS connections */
typedef struct WSState {
    /* Handshake accumulation (freed after upgrade) */
    char   *hs_buf;
    int     hs_len;

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

/* Framing — called from send.c send_message() */
int  ws_frame_message(const char *msg, int len, char *outbuf);

/* Control frames */
void ws_send_close(aClient *cptr, int code, const char *reason);
void ws_send_pong(aClient *cptr, const char *data, int len);

#endif /* WEBSOCKET_H */
