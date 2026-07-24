/*
 * base64.c — RFC 4648 Base64 encode/decode
 */

#include "base64.h"
#include <string.h>

static const char b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Decode table: -1 = invalid, -2 = padding ('=') */
static const signed char b64dec[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-2,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

int
base64_decode(const char *in, unsigned char *out, int outmax)
{
    int           len = 0;
    unsigned int  acc = 0;
    int           bits = 0;
    const unsigned char *p;

    for (p = (const unsigned char *)in; *p; p++)
    {
        signed char v = b64dec[*p];
        if (v == -2)
            break;  /* padding — stop */
        if (v == -1)
            return -1;  /* invalid character */

        acc = (acc << 6) | (unsigned int)v;
        bits += 6;

        if (bits >= 8)
        {
            bits -= 8;
            if (len >= outmax)
                return -1;
            out[len++] = (unsigned char)(acc >> bits);
            acc &= (1u << bits) - 1;
        }
    }

    return len;
}

int
base64_encode(const unsigned char *in, int inlen, char *out, int outmax)
{
    int i, len = 0;
    int needed = ((inlen + 2) / 3) * 4 + 1;

    if (needed > outmax)
        return -1;

    for (i = 0; i < inlen; i += 3)
    {
        unsigned int n = (unsigned int)in[i] << 16;
        if (i + 1 < inlen) n |= (unsigned int)in[i + 1] << 8;
        if (i + 2 < inlen) n |= (unsigned int)in[i + 2];

        out[len++] = b64chars[(n >> 18) & 0x3F];
        out[len++] = b64chars[(n >> 12) & 0x3F];
        out[len++] = (i + 1 < inlen) ? b64chars[(n >> 6) & 0x3F] : '=';
        out[len++] = (i + 2 < inlen) ? b64chars[n & 0x3F] : '=';
    }

    out[len] = '\0';
    return len;
}
