#ifndef DH_HEADER
extern int dh_init();
extern void dh_end_session(void *);
extern void *dh_start_session();
extern char *dh_get_s_public(char *, size_t, void *);
extern int dh_get_s_shared(unsigned char *, size_t *, void *);
extern int dh_generate_shared(void *, char *);

extern int dh_hexstr_to_raw(char *string, unsigned char *hexout, int *hexlen);

extern void rc4_process_stream_to_buf(void *rc4_context, const char *istring,
                               char *ostring, unsigned int stringlen);
extern void rc4_process_stream(void *rc4_context, char *istring, unsigned int stringlen);
extern void *rc4_initstate(unsigned char *key, int keylen);
extern void rc4_destroystate(void *a);

#else

/* this stuff is only included for dh.c .. this is a kludge,
 * but our header files are fucking disgusting anyway.
 */

struct session_info
{
    DH *dh;
    unsigned char *session_shared;
    size_t session_shared_length;
};

/*
 * Do not change these unless
 * you also change the prime below
 */

#define KEY_BITS 512

#define RAND_BITS KEY_BITS
#define RAND_BYTES (RAND_BITS / 8)
#define RAND_BYTES_HEX ((RAND_BYTES * 2) + 1)

#define PRIME_BITS 1024
#define PRIME_BYTES (PRIME_BITS / 8)
#define PRIME_BYTES_HEX ((PRIME_BYTES * 2) + 1)

static BIGNUM *ircd_prime;
static BIGNUM *ircd_generator;

#undef hex_to_string /* Defined by OpenSSL >= 3.0 */
static char *hex_to_string[256] =
{
    "00", "01", "02", "03", "04", "05", "06", "07",
    "08", "09", "0a", "0b", "0c", "0d", "0e", "0f",
    "10", "11", "12", "13", "14", "15", "16", "17",
    "18", "19", "1a", "1b", "1c", "1d", "1e", "1f",
    "20", "21", "22", "23", "24", "25", "26", "27",
    "28", "29", "2a", "2b", "2c", "2d", "2e", "2f",
    "30", "31", "32", "33", "34", "35", "36", "37",
    "38", "39", "3a", "3b", "3c", "3d", "3e", "3f",
    "40", "41", "42", "43", "44", "45", "46", "47",
    "48", "49", "4a", "4b", "4c", "4d", "4e", "4f",
    "50", "51", "52", "53", "54", "55", "56", "57",
    "58", "59", "5a", "5b", "5c", "5d", "5e", "5f",
    "60", "61", "62", "63", "64", "65", "66", "67",
    "68", "69", "6a", "6b", "6c", "6d", "6e", "6f",
    "70", "71", "72", "73", "74", "75", "76", "77",
    "78", "79", "7a", "7b", "7c", "7d", "7e", "7f",
    "80", "81", "82", "83", "84", "85", "86", "87",
    "88", "89", "8a", "8b", "8c", "8d", "8e", "8f",
    "90", "91", "92", "93", "94", "95", "96", "97",
    "98", "99", "9a", "9b", "9c", "9d", "9e", "9f",
    "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7",
    "a8", "a9", "aa", "ab", "ac", "ad", "ae", "af",
    "b0", "b1", "b2", "b3", "b4", "b5", "b6", "b7",
    "b8", "b9", "ba", "bb", "bc", "bd", "be", "bf",
    "c0", "c1", "c2", "c3", "c4", "c5", "c6", "c7",
    "c8", "c9", "ca", "cb", "cc", "cd", "ce", "cf",
    "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7",
    "d8", "d9", "da", "db", "dc", "dd", "de", "df",
    "e0", "e1", "e2", "e3", "e4", "e5", "e6", "e7",
    "e8", "e9", "ea", "eb", "ec", "ed", "ee", "ef",
    "f0", "f1", "f2", "f3", "f4", "f5", "f6", "f7",
    "f8", "f9", "fa", "fb", "fc", "fd", "fe", "ff"
};

/* This prime is taken from IPsec */

static unsigned int dh_gen_1024 = 2;
static unsigned char dh_prime_1024[] =
{
        0xF4, 0x88, 0xFD, 0x58, 0x4E, 0x49, 0xDB, 0xCD,
        0x20, 0xB4, 0x9D, 0xE4, 0x91, 0x07, 0x36, 0x6B,
        0x33, 0x6C, 0x38, 0x0D, 0x45, 0x1D, 0x0F, 0x7C,
        0x88, 0xB3, 0x1C, 0x7C, 0x5B, 0x2D, 0x8E, 0xF6,
        0xF3, 0xC9, 0x23, 0xC0, 0x43, 0xF0, 0xA5, 0x5B,
        0x18, 0x8D, 0x8E, 0xBB, 0x55, 0x8C, 0xB8, 0x5D,
        0x38, 0xD3, 0x34, 0xFD, 0x7C, 0x17, 0x57, 0x43,
        0xA3, 0x1D, 0x18, 0x6C, 0xDE, 0x33, 0x21, 0x2C,
        0xB5, 0x2A, 0xFF, 0x3C, 0xE1, 0xB1, 0x29, 0x40,
        0x18, 0x11, 0x8D, 0x7C, 0x84, 0xA7, 0x0A, 0x72,
        0xD6, 0x86, 0xC4, 0x03, 0x19, 0xC8, 0x07, 0x29,
        0x7A, 0xCA, 0x95, 0x0C, 0xD9, 0x96, 0x9F, 0xAB,
        0xD0, 0x0A, 0x50, 0x9B, 0x02, 0x46, 0xD3, 0x08,
        0x3D, 0x66, 0xA4, 0x5D, 0x41, 0x9F, 0x9C, 0x7C,
        0xBD, 0x89, 0x4B, 0x22, 0x19, 0x26, 0xBA, 0xAB,
        0xA2, 0x5E, 0xC3, 0x55, 0xE9, 0x2F, 0x78, 0xC7
};

/*
 * These are too big for ircd. :\
static unsigned int dh_gen_2048 = 2;
static unsigned char dh_prime_2048[] = {
        0xF6, 0x42, 0x57, 0xB7, 0x08, 0x7F, 0x08, 0x17,
        0x72, 0xA2, 0xBA, 0xD6, 0xA9, 0x42, 0xF3, 0x05,
        0xE8, 0xF9, 0x53, 0x11, 0x39, 0x4F, 0xB6, 0xF1,
        0x6E, 0xB9, 0x4B, 0x38, 0x20, 0xDA, 0x01, 0xA7,
        0x56, 0xA3, 0x14, 0xE9, 0x8F, 0x40, 0x55, 0xF3,
        0xD0, 0x07, 0xC6, 0xCB, 0x43, 0xA9, 0x94, 0xAD,
        0xF7, 0x4C, 0x64, 0x86, 0x49, 0xF8, 0x0C, 0x83,
        0xBD, 0x65, 0xE9, 0x17, 0xD4, 0xA1, 0xD3, 0x50,
        0xF8, 0xF5, 0x59, 0x5F, 0xDC, 0x76, 0x52, 0x4F,
        0x3D, 0x3D, 0x8D, 0xDB, 0xCE, 0x99, 0xE1, 0x57,
        0x92, 0x59, 0xCD, 0xFD, 0xB8, 0xAE, 0x74, 0x4F,
        0xC5, 0xFC, 0x76, 0xBC, 0x83, 0xC5, 0x47, 0x30,
        0x61, 0xCE, 0x7C, 0xC9, 0x66, 0xFF, 0x15, 0xF9,
        0xBB, 0xFD, 0x91, 0x5E, 0xC7, 0x01, 0xAA, 0xD3,
        0x5B, 0x9E, 0x8D, 0xA0, 0xA5, 0x72, 0x3A, 0xD4,
        0x1A, 0xF0, 0xBF, 0x46, 0x00, 0x58, 0x2B, 0xE5,
        0xF4, 0x88, 0xFD, 0x58, 0x4E, 0x49, 0xDB, 0xCD,
        0x20, 0xB4, 0x9D, 0xE4, 0x91, 0x07, 0x36, 0x6B,
        0x33, 0x6C, 0x38, 0x0D, 0x45, 0x1D, 0x0F, 0x7C,
        0x88, 0xB3, 0x1C, 0x7C, 0x5B, 0x2D, 0x8E, 0xF6,
        0xF3, 0xC9, 0x23, 0xC0, 0x43, 0xF0, 0xA5, 0x5B,
        0x18, 0x8D, 0x8E, 0xBB, 0x55, 0x8C, 0xB8, 0x5D,
        0x38, 0xD3, 0x34, 0xFD, 0x7C, 0x17, 0x57, 0x43,
        0xA3, 0x1D, 0x18, 0x6C, 0xDE, 0x33, 0x21, 0x2C,
        0xB5, 0x2A, 0xFF, 0x3C, 0xE1, 0xB1, 0x29, 0x40,
        0x18, 0x11, 0x8D, 0x7C, 0x84, 0xA7, 0x0A, 0x72,
        0xD6, 0x86, 0xC4, 0x03, 0x19, 0xC8, 0x07, 0x29,
        0x7A, 0xCA, 0x95, 0x0C, 0xD9, 0x96, 0x9F, 0xAB,
        0xD0, 0x0A, 0x50, 0x9B, 0x02, 0x46, 0xD3, 0x08,
        0x3D, 0x66, 0xA4, 0x5D, 0x41, 0x9F, 0x9C, 0x7C,
        0xBD, 0x89, 0x4B, 0x22, 0x19, 0x26, 0xBA, 0xAB,
        0xA2, 0x5E, 0xC3, 0x55, 0xE9, 0x32, 0x0B, 0x3B
};
 */

#endif
