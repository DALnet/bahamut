/*
 *   ircstrings.c - some string-related parsing/validation stuff for ircd
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

#include "ircstrings.h"

/*
 * This file and its associated header file are self-contained with two
 * exceptions: ircsprintf(), an ircd-specific version of sprintf(); and
 * certain identifier string length limits.  The limits are:
 *     NICKLEN      (30)
 *     USERLEN      (10)
 *     HOSTLEN      (63)
 *     CHANNELLEN   (32)
 */
#include "struct.h"
#include "h.h"


/* used to access octets of a raw ip in network byte order */
union mappedip {
    unsigned char p[4];
    unsigned int  f;
};


/* used for validcharmap[] table */
#define VCM_WILD        0x01    /* wildcard */
#define VCM_HOST        0x02    /* inside a host component */
#define VCM_HOSTSEP     0x04    /* separates host components */
#define VCM_NICKC       0x08    /* inside a nickname */
#define VCM_NICKB       0x10    /* begins a nickname */
#define VCM_NICKBC      0x18    /* can begin and be inside a nickname */
#define VCM_USER        0x20    /* inside a username */
#define VCM_DIGIT       0x40    /* is a digit */
#define VCM_ALPHA       0x80    /* is alphabetical */

#define VcmDigit(c)  (validcharmap[c] & VCM_DIGIT)
#define VcmAlpha(c)  (validcharmap[c] & VCM_ALPHA)


/* "prototypes" for tables at the bottom */
static unsigned char validcharmap[256];
static union mappedip cidr2maskmap[33];


/* process an IP octet */
static inline int
parse_octet(unsigned char **buf, unsigned char *octet)
{
    unsigned int val;
    unsigned char *s;

    s = *buf;
    val = (*s++ - '0');

    if (VcmDigit(*s))
    {
        /* no leading zeros */
        if (val == 0)
            return 0;

        val *= 10;
        val += (*s++ - '0');

        if (VcmDigit(*s))
        {
            val *= 10;
            val += (*s++ - '0');

            if (VcmDigit(*s) || val > 255)
                return 0;
        }
    }

    *octet = val;
    *buf = s;

    return 1;
}

/* process a CIDR bit length suffix */
static inline int
parse_cidr(unsigned char *s, int *prefix)
{
    int val;

    if (!VcmDigit(*s))
        return 0;

    val = (*s++ - '0');

    if (VcmDigit(*s))
    {
        val *= 10;
        val += (*s++ - '0');
    }

    if (val < 1 || val > 32)
        return 0;

    if (*s)
        return 0;

    *prefix = val;
    return 1;
}

/*
 * Try to parse an IP as a full IP, CIDR mask, or wildcard mask convertible
 * to CIDR.  This function is unrolled, so a bit long.  Returns an HMT.
 * Stores the IPv4 address in network byte order, and the prefix (1 - 32).
 * Assumptions:
 *    host contains only characters in set 0-9 . / *
 *    host contains at least one digit
 */
static int
tryparse_ip_cidr(unsigned char *host, unsigned int *outip, int *outprefix)
{
    unsigned char *s;
    union {
        unsigned int whole;
        unsigned char part[4];
    } ip;
    int prefix;
    int partidx = 0;
    int onlystar = 0;

    ip.whole = 0;

    s = host;

    /*
     * first component: octet possibly followed by /CIDR
     */
    if (VcmDigit(*s))
    {
        if (!parse_octet(&s, &ip.part[partidx++]))
            return HMT_INVALID;
    }
    else
        return HMT_INVALID;

    if (*s == '/')
    {
        if (!parse_cidr(s+1, &prefix))
            return HMT_INVALID;

        *outip = ip.whole;
        *outprefix = prefix;
        return HMT_IPCIDR;
    }

    if (*s++ != '.')
        return HMT_INVALID;

    /*
     * second component: octet possibly followed by /CIDR, or a star
     */
    if (VcmDigit(*s))
    {
        if (!parse_octet(&s, &ip.part[partidx++]))
            return HMT_INVALID;

        if (*s == '/')
        {
            if (!parse_cidr(s+1, &prefix))
                return HMT_INVALID;

            *outip = ip.whole;
            *outprefix = prefix;
            return HMT_IPCIDR;
        }
    }
    else if (*s == '*')
    {
        s++;
        onlystar++;
        prefix = 8;
    }
    else
        return HMT_INVALID;

    if (onlystar && !*s)
    {
        *outip = ip.whole;
        *outprefix = prefix;
        return HMT_IPCIDR;
    }

    if (*s++ != '.')
        return HMT_INVALID;

    /*
     * third component: octet possibly followed by /CIDR (unless onlystar),
     * or a star
     */
    if (!onlystar && VcmDigit(*s))
    {
        if (!parse_octet(&s, &ip.part[partidx++]))
            return HMT_INVALID;

        if (*s == '/')
        {
            if (!parse_cidr(s+1, &prefix))
                return HMT_INVALID;

            *outip = ip.whole;
            *outprefix = prefix;
            return HMT_IPCIDR;
        }
    }
    else if (*s == '*')
    {
        s++;
        if (!onlystar)
            prefix = 16;
        onlystar++;
    }
    else
        return HMT_INVALID;

    if (onlystar && !*s)
    {
        *outip = ip.whole;
        *outprefix = prefix;
        return HMT_IPCIDR;
    }

    if (*s++ != '.')
        return HMT_INVALID;

    /*
     * fourth component: octet possibly followed by /CIDR (unless onlystar),
     * or a star
     */
    if (!onlystar && VcmDigit(*s))
    {
        if (!parse_octet(&s, &ip.part[partidx++]))
            return HMT_INVALID;

        if (*s == '/')
        {
            if (!parse_cidr(s+1, &prefix))
                return HMT_INVALID;

            *outip = ip.whole;
            *outprefix = prefix;
            return HMT_IPCIDR;
        }

        if (!*s)
        {
            *outip = ip.whole;
            *outprefix = 32;
            return HMT_IP;
        }
    }
    else if (*s == '*')
    {
        s++;
        if (!onlystar)
            prefix = 24;

        if (!*s)
        {
            *outip = ip.whole;
            *outprefix = prefix;
            return HMT_IPCIDR;
        }
    }

    return HMT_INVALID;
}

/*
 * Try to verify a string is a valid wildcard IP mask.  Returns an HMT.
 * Assumptions:
 *     host contains only characters in set 0-9 . ? *
 *     host has at least 1 character
 */
static int
tryparse_ip_mask(unsigned char *host)
{
    unsigned char *s = host;
    unsigned char o;
    int stars = 0;
    int components = 1;
    int separator = 0;

    if (*s == '.')
        return HMT_INVALID;

    /* force first ? to be handled as a component */
    if (*s == '?')
        s++;

    while (*s)
    {
        if (VcmDigit(*s))
        {
            if (!parse_octet(&s, &o))
                return HMT_INVALID;
            separator = 0;
            continue;
        }
        if (*s == '*')
        {
            separator = 0;
            stars++;
        }
        else if (*s == '?')
        {
            if (!separator)
            {
                separator = '?';
                components++;
            }
            else
                separator = 0;
        }
        else
        {
            /* this is a dot, previous char can't be too */
            if (separator == '.')
                return HMT_INVALID;
            if (!separator)
                components++;
            separator = '.';
        }
        s++;
    }

    /* last char can't be a dot */
    if (s[-1] == '.')
        return HMT_INVALID;

    if (!stars)
    {
        /* dot check is above, so separator can only be '?' */
        if (separator)
            components--;

        /* not enough possible dot-separated components to match a full IP */
        if (components < 4)
            return HMT_INVALID;
    }

    if ((s - host - stars) > HOSTIPLEN)
        return HMT_INVALID;

    return HMT_IPMASK;
}


/*
 * Categorize the supplied host mask.  For valid IPv4 CIDR masks, outip is
 * filled with a parsed IPv4 address in network byte order, and prefix with
 * the CIDR bit length.  Returns an HMT.
 * Supported options:
 *     VALIDATE_DOT
 */
int
categorize_host(char *host, unsigned int *outip, int *outprefix, int opts)
{
    unsigned char *s;
    int digitcount = 0;
    int alphacount = 0;
    int dotcount = 0;
    int dashcount = 0;
    int slashcount = 0;
    int starcount = 0;
    int questcount = 0;
    int rv;

    for (s = host; *s; s++)
    {
        if (VcmAlpha(*s))
            alphacount++;
        else if (VcmDigit(*s))
            digitcount++;
        else if (*s == '.')
            dotcount++;
        else if (*s == '-')
            dashcount++;
        else if (*s == '/')
            slashcount++;
        else if (*s == '*')
            starcount++;
        else if (*s == '?')
            questcount++;
        else
            return HMT_INVALID;
    }
    /* NOTE: s is used as-is below */

    /* wildcards */
    if (!digitcount && !alphacount && !dashcount && !slashcount)
    {
        /* stars and maybe some dots, matches any IP */
        if (starcount && !questcount && dotcount <= 3)
        {
            /* but only if the dots form a valid hostmask */
            if (dotcount && !validate_host(host, VALIDATE_MASK))
                return HMT_INVALID;

            return HMT_WILD;
        }

        /* empty, or only dots and wildcards */
        return HMT_INVALID;
    }

    /* substance required */
    if (!digitcount && !alphacount)
        return HMT_INVALID;

    /* IP like */
    if (digitcount && !alphacount && !dashcount)
    {
        /* CIDR has one slash */
        if (slashcount > 1)
            return HMT_INVALID;

        /* never more than 3 dots or 12 digits in an IP */
        if (dotcount <= 3 && digitcount <= 12)
        {
            if (!questcount)
            {
                /* could be full IP, CIDR, or convertible to CIDR */
                if ((rv = tryparse_ip_cidr(host, outip, outprefix)))
                {
                    *outip &= cidr2maskmap[*outprefix].f;
                    return rv;
                }
            }

            /* can't be converted to CIDR, so must contain no slash */
            if (slashcount)
                return HMT_INVALID;

            /* see if it's acceptable as an IP mask */
            if ((rv = tryparse_ip_mask(host)))
            {
                if ((opts & VALIDATE_DOT) && !dotcount)
                    return HMT_INVALID;
                return rv;
            }
        }
    }

    /* only CIDR can have a slash */
    if (slashcount)
        return HMT_INVALID;

    /* caller demands a dot */
    if ((opts & VALIDATE_DOT) && !dotcount)
        return HMT_INVALID;

    /* full hostname */
    if (!starcount && !questcount)
    {
        if (!validate_host(host, VALIDATE_NAME))
            return HMT_INVALID;

        return HMT_NAME;
    }

    /* can only be a hostname mask */
    if (validate_host(host, VALIDATE_MASK|VALIDATE_NAME))
        return HMT_NAMEMASK;

    return HMT_INVALID;
}


/*
 * Validate a nick name or mask.  Returns 1 if valid, 0 otherwise.
 * Supported options:
 *     VALIDATE_MASK
 */
int
validate_nick(char *nick, int opts)
{
    unsigned char *s = nick;
    int length;
    int stars = 0;

    if (opts & VALIDATE_MASK)
    {
        if (!(validcharmap[*s] & (VCM_NICKB|VCM_WILD)))
            return 0;

        if (*s++ == '*')
            stars++;

        while (*s)
        {
            if (!(validcharmap[*s] & (VCM_NICKC|VCM_WILD)))
                return 0;

            if (*s++ == '*')
                stars++;
        }
    }
    else
    {
        if (!(validcharmap[*s++] & VCM_NICKB))
            return 0;

        while (*s)
            if (!(validcharmap[*s++] & VCM_NICKC))
                return 0;
    }

    length = s - (unsigned char *)nick;

    if (length < 1)
        return 0;

    if ((length - stars) > NICKLEN)
        return 0;

    /* XXX: reevaluate this */
    if (stars > 5)
        return 0;

    return 1;
}


/*
 * Validate a user name or mask.  Returns 1 if valid, 0 otherwise.
 * Supported options:
 *     VALIDATE_MASK
 *     VALIDATE_PREREG
 */
int
validate_user(char *user, int opts)
{
    unsigned char *s = user;
    int length;
    int stars = 0;

    if (opts & VALIDATE_PREREG)
    {
        /* starting with '~' or '-' is reserved */
        if (*s == '~' || *s == '-')
            return 0;
    }

    if (opts & VALIDATE_MASK)
    {
        do {
            if (!(validcharmap[*s] & (VCM_USER|VCM_WILD)))
                return 0;

            if (*s++ == '*')
                stars++;
        } while (*s);
    }
    else
    {
        do {
            if (!(validcharmap[*s++] & VCM_USER))
                return 0;
        } while (*s);
    }

    length = s - (unsigned char *)user;

    if (length < 1)
        return 0;

    if ((length - stars) > USERLEN)
        return 0;

    /* XXX: reevaluate this */
    if (stars > 3)
        return 0;

    return 1;
}


/*
 * Validate a host name or mask (IPv4 strings are a subset of this).
 * Returns 1 if valid, 0 otherwise.
 * Supported options:
 *     VALIDATE_MASK
 *     VALIDATE_DOT
 *     VALIDATE_NAME
 */
int
validate_host(char *host, int opts)
{
    unsigned char *s = host;
    unsigned char vcm = 0;
    int length;
    int stars = 0;

    if (opts & VALIDATE_MASK)
    {
        /* dual loops: VCM_HOST strings separated by VCM_HOSTSEP or VCM_WILD */
        do {
            if (!(validcharmap[*s] & (VCM_HOST|VCM_WILD)))
                return 0;

            if (*s++ == '*')
                stars++;

            while (*s)
            {
                vcm = validcharmap[*s++];

                if (!(vcm & (VCM_HOST|VCM_HOSTSEP|VCM_WILD)))
                    return 0;

                if (vcm & (VCM_HOSTSEP|VCM_WILD))
                    break;
            }
        } while (*s);
    }
    else
    {
        /* dual loops: VCM_HOST strings separated by VCM_HOSTSEP */
        do {
            if (!(validcharmap[*s++] & VCM_HOST))
                return 0;

            while (*s)
            {
                vcm = validcharmap[*s++];

                if (!(vcm & (VCM_HOST|VCM_HOSTSEP)))
                    return 0;

                if (vcm & VCM_HOSTSEP)
                    break;
            }
        } while (*s);
    }

    length = s - (unsigned char *)host;

    if (length < 1)
        return 0;

    if ((length - stars) > HOSTLEN)
        return 0;

    /* XXX: reevaluate this */
    if (stars > 10)
        return 0;

    /* can't end in HOSTSEP */
    if (vcm & VCM_HOSTSEP)
        return 0;

    /* must be capable of matching at least a two character TLD */
    if (opts & VALIDATE_NAME)
    {
        unsigned char lc = 0;  /* last char */
        unsigned char slc = 0; /* second-to-last char */

        lc = s[-1];
        if (length >= 2)
            slc = s[-2];

        if (opts & VALIDATE_MASK)
        {
            if (lc != '*')
            {
                if (lc != '?' && !VcmAlpha(lc))
                    return 0;

                if (!(validcharmap[slc] & VCM_WILD) && !VcmAlpha(slc))
                    return 0;
            }
        }
        else
        {
            if (!(VcmAlpha(lc) && VcmAlpha(slc)))
                return 0;
        }
    }

    if ((opts & VALIDATE_DOT) && !strchr(host, '.'))
        return 0;

    return 1;
}

/*
 * Validate a channel name or mask.  Returns 1 if valid, 0 otherwise.
 * Supported options:
 *     VALIDATE_MASK
 */
int
validate_channel(char *name, int opts)
{
    unsigned char *s = name;
    int length;
    int stars = 0;

    /* Validation is done algorithmically as exclusions, instead of listing
     * permitted values in the lookup table. */

    /* if not a wildcard mask, must begin with # */
    if (!(opts & VALIDATE_MASK))
    {
        if (*s++ != '#')
            return 0;
    }

    while (*s)
    {
        /* not allowed: control, space, comma, ISO 8859-1 no-break space */
        if (*s < 33 || *s == ',' || *s == 160)
            return 0;

        if (*s++ == '*')
            stars++;
    }

    length = s - (unsigned char *)name;

    if (opts & VALIDATE_MASK)
    {
        if ((length - stars) > CHANNELLEN)
            return 0;

        /* XXX: reevaluate this */
        if (stars > 10)
            return 0;
    }
    else
    {
        if (length > CHANNELLEN)
            return 0;
    }

    return 1;
}


/*
 * Convert a CIDR prefix bitcount into a netmask.
 * Returned mask is in network byte order.
 */
unsigned int
cidr2mask(int prefix)
{
    if (prefix < 0)
        prefix = 0;

    if (prefix > 32)
        prefix = 32;

    return cidr2maskmap[prefix].f;
}


/*
 * Convert an IP and CIDR prefix into a string, preferring wildcard mask
 * notation if specified.
 * Returns a pointer to a static char buffer.
 */
char *
cidr2string(unsigned int rawip, int prefix, int prefermask)
{
    static char buf[20];
    union mappedip ip;

    ip.f = rawip;

    if (prefix == 32)
        ircsprintf(buf, "%d.%d.%d.%d", ip.p[0], ip.p[1], ip.p[2], ip.p[3]);
    else if (prefix > 24)
        ircsprintf(buf, "%d.%d.%d.%d/%d", ip.p[0], ip.p[1], ip.p[2], ip.p[3],
                   prefix);
    else if (prefermask && prefix == 24)
        ircsprintf(buf, "%d.%d.%d.*", ip.p[0], ip.p[1], ip.p[2]);
    else if (prefix > 16)
        ircsprintf(buf, "%d.%d.%d/%d", ip.p[0], ip.p[1], ip.p[2], prefix);
    else if (prefermask && prefix == 16)
        ircsprintf(buf, "%d.%d.*", ip.p[0], ip.p[1]);
    else if (prefix > 8)
        ircsprintf(buf, "%d.%d/%d", ip.p[0], ip.p[1], prefix);
    else if (prefermask && prefix == 8)
        ircsprintf(buf, "%d.*", ip.p[0]);
    else
        ircsprintf(buf, "%d/%d", ip.p[0], prefix);

    return buf;
}


static unsigned char validcharmap[256] = {
    /* dec hex name */  /* flags */
    /* --- --- ---- */
    /*   0   0  nul */  0,
    /*   1   1  soh */  0,
    /*   2   2  stx */  0,
    /*   3   3  etx */  0,
    /*   4   4  eot */  0,
    /*   5   5  enq */  0,
    /*   6   6  ack */  0,
    /*   7   7  bel */  0,

    /*   8   8   bs */  0,
    /*   9   9  tab */  0,
    /*  10   a   lf */  0,
    /*  11   b   vt */  0,
    /*  12   c   ff */  0,
    /*  13   d   cr */  0,
    /*  14   e   so */  0,
    /*  15   f   si */  0,

    /*  16  10  dle */  0,
    /*  17  11  dc1 */  0,
    /*  18  12  dc2 */  0,
    /*  19  13  dc3 */  0,
    /*  20  14  dc4 */  0,
    /*  21  15  nak */  0,
    /*  22  16  syn */  0,
    /*  23  17  etb */  0,

    /*  24  18  can */  0,
    /*  25  19   em */  0,
    /*  26  1a  sub */  0,
    /*  27  1b  esc */  0,
    /*  28  1c   fs */  0,
    /*  29  1d   gs */  0,
    /*  30  1e   rs */  0,
    /*  31  1f   us */  0,

    /*  32  20      */  0,
    /*  33  21    ! */  0,
    /*  34  22    " */  0,
    /*  35  23    # */  0,
    /*  36  24    $ */  0,
    /*  37  25    % */  0,
    /*  38  26    & */  0,
    /*  39  27    ' */  0,

    /*  40  28    ( */  0,
    /*  41  29    ) */  0,
    /*  42  2a    * */  VCM_WILD,
    /*  43  2b    + */  0,
    /*  44  2c    , */  0,
    /*  45  2d    - */  VCM_NICKC  | VCM_USER | VCM_HOSTSEP,
    /*  46  2e    . */               VCM_USER | VCM_HOSTSEP,
    /*  47  2f    / */  0,

    /*  48  30    0 */  VCM_NICKC  | VCM_USER | VCM_HOST    | VCM_DIGIT,
    /*  49  31    1 */  VCM_NICKC  | VCM_USER | VCM_HOST    | VCM_DIGIT,
    /*  50  32    2 */  VCM_NICKC  | VCM_USER | VCM_HOST    | VCM_DIGIT,
    /*  51  33    3 */  VCM_NICKC  | VCM_USER | VCM_HOST    | VCM_DIGIT,
    /*  52  34    4 */  VCM_NICKC  | VCM_USER | VCM_HOST    | VCM_DIGIT,
    /*  53  35    5 */  VCM_NICKC  | VCM_USER | VCM_HOST    | VCM_DIGIT,
    /*  54  36    6 */  VCM_NICKC  | VCM_USER | VCM_HOST    | VCM_DIGIT,
    /*  55  37    7 */  VCM_NICKC  | VCM_USER | VCM_HOST    | VCM_DIGIT,

    /*  56  38    8 */  VCM_NICKC  | VCM_USER | VCM_HOST    | VCM_DIGIT,
    /*  57  39    9 */  VCM_NICKC  | VCM_USER | VCM_HOST    | VCM_DIGIT,
    /*  58  3a    : */  0,
    /*  59  3b    ; */  0,
    /*  60  3c    < */  0,
    /*  61  3d    = */  0,
    /*  62  3e    > */  0,
    /*  63  3f    ? */  VCM_WILD,

    /*  64  40    @ */  0,
    /*  65  41    A */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  66  42    B */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  67  43    C */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  68  44    D */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  69  45    E */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  70  46    F */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  71  47    G */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,

    /*  72  48    H */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  73  49    I */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  74  4a    J */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  75  4b    K */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  76  4c    L */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  77  4d    M */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  78  4e    N */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  79  4f    O */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,

    /*  80  50    P */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  81  51    Q */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  82  52    R */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  83  53    S */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  84  54    T */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  85  55    U */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  86  56    V */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  87  57    W */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,

    /*  88  58    X */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  89  59    Y */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  90  5a    Z */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  91  5b    [ */  VCM_NICKBC | VCM_USER,
    /*  92  5c    \ */  VCM_NICKBC | VCM_USER,
    /*  93  5d    ] */  VCM_NICKBC | VCM_USER,
    /*  94  5e    ^ */  VCM_NICKBC | VCM_USER,
    /*  95  5f    _ */  VCM_NICKBC | VCM_USER,

    /*  96  60    ` */  VCM_NICKBC,
    /*  97  61    a */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  98  62    b */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /*  99  63    c */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 100  64    d */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 101  65    e */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 102  66    f */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 103  67    g */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,

    /* 104  68    h */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 105  69    i */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 106  6a    j */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 107  6b    k */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 108  6c    l */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 109  6d    m */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 110  6e    n */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 111  6f    o */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,

    /* 112  70    p */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 113  71    q */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 114  72    r */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 115  73    s */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 116  74    t */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 117  75    u */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 118  76    v */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 119  77    w */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,

    /* 120  78    x */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 121  79    y */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 122  7a    z */  VCM_NICKBC | VCM_USER | VCM_HOST    | VCM_ALPHA,
    /* 123  7b    { */  VCM_NICKBC | VCM_USER,
    /* 124  7c    | */  VCM_NICKBC | VCM_USER,
    /* 125  7d    } */  VCM_NICKBC | VCM_USER,
    /* 126  7e    ~ */               VCM_USER,
    /* 127  7f  del */  0

    /* rest are zero */
};

static union mappedip cidr2maskmap[33] = {
    {{0x00,0x00,0x00,0x00}}, {{0x80,0x00,0x00,0x00}}, {{0xc0,0x00,0x00,0x00}},
    {{0xe0,0x00,0x00,0x00}}, {{0xf0,0x00,0x00,0x00}}, {{0xf8,0x00,0x00,0x00}},
    {{0xfc,0x00,0x00,0x00}}, {{0xfe,0x00,0x00,0x00}}, {{0xff,0x00,0x00,0x00}},
    {{0xff,0x80,0x00,0x00}}, {{0xff,0xc0,0x00,0x00}}, {{0xff,0xe0,0x00,0x00}},
    {{0xff,0xf0,0x00,0x00}}, {{0xff,0xf8,0x00,0x00}}, {{0xff,0xfc,0x00,0x00}},
    {{0xff,0xfe,0x00,0x00}}, {{0xff,0xff,0x00,0x00}}, {{0xff,0xff,0x80,0x00}},
    {{0xff,0xff,0xc0,0x00}}, {{0xff,0xff,0xe0,0x00}}, {{0xff,0xff,0xf0,0x00}},
    {{0xff,0xff,0xf8,0x00}}, {{0xff,0xff,0xfc,0x00}}, {{0xff,0xff,0xfe,0x00}},
    {{0xff,0xff,0xff,0x00}}, {{0xff,0xff,0xff,0x80}}, {{0xff,0xff,0xff,0xc0}},
    {{0xff,0xff,0xff,0xe0}}, {{0xff,0xff,0xff,0xf0}}, {{0xff,0xff,0xff,0xf8}},
    {{0xff,0xff,0xff,0xfc}}, {{0xff,0xff,0xff,0xfe}}, {{0xff,0xff,0xff,0xff}}
};

