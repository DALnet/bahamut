#ifndef BASE64_H
#define BASE64_H

/* RFC 4648 Base64 encode/decode.
 * Returns output length on success, -1 on error (truncation or bad input). */
int base64_decode(const char *in, unsigned char *out, int outmax);
int base64_encode(const unsigned char *in, int inlen, char *out, int outmax);

#endif /* BASE64_H */
