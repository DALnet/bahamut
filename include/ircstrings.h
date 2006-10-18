#ifndef IRCSTRINGS_H
#define IRCSTRINGS_H
/*
 *   ircstrings.h - some string-related parsing/validation stuff for ircd
 *
 *   Copyright (c) 2006 Trevor Talbot and the DALnet coding team
 *   All rights reserved.
 *
 *   Permission is hereby granted, free of charge, to any person obtaining a
 *   copy of this Software, to deal in the Software without restriction,
 *   including without limitation the rights to use, copy, modify, merge,
 *   publish, distribute, sublicense, and/or sell copies of the Software, and
 *   to permit persons to whom the Software is furnished to do so, subject to
 *   the following conditions:
 *
 *   The above copyright notice and this permission notice shall be included
 *   in all copies or substantial portions of the Software.
 *
 *   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 *   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *   MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 *   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 *   CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 *   TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 *   SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* $Id$ */

/* hostmask types */
#define HMT_INVALID     0
#define HMT_WILD        1   /* wildcard, matches anything */
#define HMT_NAME        2   /* a full hostname string */
#define HMT_NAMEMASK    3   /* a wildcard hostname mask string */
#define HMT_IP          4   /* a full IP address */
#define HMT_IPCIDR      5   /* a CIDR IP mask */
#define HMT_IPMASK      6   /* a wildcard IP mask string */

/* validation options */
#define VALIDATE_MASK   0x01    /* can contain wildcards */
#define VALIDATE_DOT    0x02    /* dot required */
#define VALIDATE_NAME   0x04    /* must match a domain name */
#define VALIDATE_PREREG 0x08    /* pre-registration stage */


int categorize_host(char *, unsigned int *, int *, int);

int validate_nick(char *, int);
int validate_user(char *, int);
int validate_host(char *, int);
int validate_channel(char *, int);

unsigned int cidr2mask(int);
char *cidr2string(unsigned int, int, int);


#endif  /* IRCSTRINGS_H */
