/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996,1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

#define NS_IN6ADDRSZ 16
#define NS_INT16SZ 2
#define NS_INADDRSZ 4

#define IsDigit(c) ((c) >= '0' && (c) <= '9')

static int inet_parse_cidr_ipv4(const char *src, unsigned char *dst, size_t size);
static int inet_parse_cidr_ipv6(const char *src, unsigned char *dst, size_t size);
int inet_parse_cidr(int af, const char *src, void *dst, size_t size);

/*
 * int inet_parse_cidr(af, src, dst, size)
 *	convert network address from presentation to network format.
 *	accepts inet_pton()'s input plus trailing "/CIDR".
 * return:
 *	number of bits specified in the /CIDR prefix length, which can
 *	have defaults (like /32 for IPv4) or -1 if an error occurred.
 * note:
 *	192.5.5.1/28 has a nonzero host part, which means it isn't a network
 *	as called for by inet_cidr_pton() but it can be a host address with
 *	an included netmask.
 * author:
 *	Paul Vixie (ISC), October 1998
 *
 *	Ned Crigler, March 2011 - functions imported from PostgreSQL with
 *	trailing .* wildcard support added.
 */
int
inet_parse_cidr(int af, const char *src, void *dst, size_t size)
{
	unsigned char *ucdst = (unsigned char *)dst;

	if (af == AF_INET)
		return inet_parse_cidr_ipv4(src, ucdst, size);
	else if (af == AF_INET6)
		return inet_parse_cidr_ipv6(src, ucdst, size);
	else
	{
		errno = EAFNOSUPPORT;
		return -1;
	}
}

static int
inet_parse_cidr_ipv4(const char *src, unsigned char *dst, size_t size)
{
	const unsigned char *odst = dst;
	int			n,
				ch,
				tmp,
				bits;

	if (size < NS_INADDRSZ)
		goto emsgsize;
	else
		size = NS_INADDRSZ;

	/* Get the mantissa. */
	while (ch = *src++, IsDigit((unsigned char) ch))
	{
		tmp = 0;
		do
		{
			n = (int)ch - '0';
			tmp *= 10;
			tmp += n;
			if (tmp > 255)
				goto enoent;
		} while ((ch = *src++) != '\0' && IsDigit((unsigned char) ch));
		if (size-- == 0)
			goto emsgsize;
		*dst++ = (unsigned char) tmp;
		if (ch == '\0' || ch == '/')
			break;
		if (ch != '.')
			goto enoent;

		/* Handle a trailing .* wildcard. */
		if (src[0] == '*' && src[1] == '\0' && dst - odst < 4)
		{
			bits = (dst - odst) * 8;

			/* Extend address to four octets. */
			while (size-- > 0)
				*dst++ = 0;
			return bits;
		}
	}

	/* Get the prefix length if any. */
	bits = -1;
	if (ch == '/' && IsDigit((unsigned char) src[0]) && dst > odst)
	{
		/* CIDR width specifier.  Nothing can follow it. */
		ch = *src++;			/* Skip over the /. */
		bits = 0;
		do
		{
			n = (int)ch - '0';
			bits *= 10;
			bits += n;
		} while ((ch = *src++) != '\0' && IsDigit((unsigned char) ch));
		if (ch != '\0')
			goto enoent;
		if (bits > 32)
			goto emsgsize;
	}

	/* Firey death and destruction unless we prefetched EOS. */
	if (ch != '\0')
		goto enoent;

	/* Prefix length can default to /32 only if all four octets spec'd. */
	if (bits == -1)
	{
		if (dst - odst == 4)
			bits = 32;
		else
			goto enoent;
	}

	/* If nothing was written to the destination, we found no address. */
	if (dst == odst)
		goto enoent;

	/* If prefix length overspecifies mantissa, life is bad. */
	if ((bits / 8) > (dst - odst))
		goto enoent;

	/* Extend address to four octets. */
	while (size-- > 0)
		*dst++ = 0;

	return bits;

enoent:
	errno = ENOENT;
	return (-1);

emsgsize:
	errno = EMSGSIZE;
	return (-1);
}

static int
getbits(const char *src, int *bitsp)
{
	int			n;
	int			val;
	char		ch;

	val = 0;
	n = 0;
	while ((ch = *src++) != '\0')
	{
		if (ch >= '0' && ch <= '9')
		{
			if (n++ != 0 && val == 0)	/* no leading zeros */
				return (0);
			val *= 10;
			val += (int)ch - '0';
			if (val > 128)		/* range */
				return (0);
			continue;
		}
		return (0);
	}
	if (n == 0)
		return (0);
	*bitsp = val;
	return (1);
}

static int
getv4(const char *src, unsigned char *dst, int *bitsp)
{
	unsigned char	   *odst = dst;
	int			n;
	unsigned int		val;
	char		ch;

	val = 0;
	n = 0;
	while ((ch = *src++) != '\0')
	{
		if (IsDigit(ch))
		{
			if (n++ != 0 && val == 0)	/* no leading zeros */
				return (0);
			val *= 10;
			val += (unsigned int)ch - '0';
			if (val > 255)		/* range */
				return (0);
			continue;
		}
		if (ch == '.' || ch == '/')
		{
			if (dst - odst > 3) /* too many octets? */
				return (0);
			*dst++ = (unsigned char)val;
			if (ch == '/')
				return (getbits(src, bitsp));
			val = 0;
			n = 0;
			continue;
		}
		return (0);
	}
	if (n == 0)
		return (0);
	if (dst - odst > 3)			/* too many octets? */
		return (0);
	*dst++ = (unsigned char)val;
	return (1);
}

static int
inet_parse_cidr_ipv6(const char *src, unsigned char *dst, size_t size)
{
	static const char xdigits_l[] = "0123456789abcdef",
				xdigits_u[] = "0123456789ABCDEF";
	unsigned char		tmp[NS_IN6ADDRSZ],
			   *tp,
			   *endp,
			   *colonp;
	const char *xdigits,
			   *curtok;
	int			ch,
				saw_xdigit;
	unsigned int		val;
	int			digits;
	int			bits;

	if (size < NS_IN6ADDRSZ)
		goto emsgsize;

	memset((tp = tmp), '\0', NS_IN6ADDRSZ);
	endp = tp + NS_IN6ADDRSZ;
	colonp = NULL;
	/* Leading :: requires some special handling. */
	if (*src == ':')
		if (*++src != ':')
			goto enoent;
	curtok = src;
	saw_xdigit = 0;
	val = 0;
	digits = 0;
	bits = -1;
	while ((ch = *src++) != '\0')
	{
		const char *pch;

		if ((pch = strchr((xdigits = xdigits_l), ch)) == NULL)
			pch = strchr((xdigits = xdigits_u), ch);
		if (pch != NULL)
		{
			val <<= 4;
			val |= (unsigned int)(pch - xdigits);
			if (++digits > 4)
				goto enoent;
			saw_xdigit = 1;
			continue;
		}
		if (ch == ':')
		{
			curtok = src;
			if (!saw_xdigit)
			{
				if (colonp)
					goto enoent;
				colonp = tp;
				continue;
			}
			else if (*src == '\0')
				goto enoent;
			if (endp - tp < NS_INT16SZ)
				goto emsgsize;
			*tp++ = (unsigned char) (val >> 8) & 0xff;
			*tp++ = (unsigned char) val & 0xff;
			saw_xdigit = 0;
			digits = 0;
			val = 0;
			continue;
		}
		if (ch == '.' && (endp - tp <= NS_INADDRSZ) &&
			getv4(curtok, tp, &bits) > 0)
		{
			tp += NS_INADDRSZ;
			saw_xdigit = 0;
			break;				/* '\0' was seen by inet_pton4(). */
		}
		if (ch == '/' && getbits(src, &bits) > 0)
			break;
		goto enoent;
	}
	if (saw_xdigit)
	{
		if (endp - tp < NS_INT16SZ)
			goto enoent;
		*tp++ = (unsigned char) (val >> 8) & 0xff;
		*tp++ = (unsigned char) val & 0xff;
	}
	if (bits == -1)
		bits = 128;

	endp = tmp + 16;

	if (colonp != NULL)
	{
		/*
		 * Since some memmove()'s erroneously fail to handle overlapping
		 * regions, we'll do the shift by hand.
		 */
		const int	n = (int)(tp - colonp);
		int			i;

		if (tp == endp)
			goto enoent;
		for (i = 1; i <= n; i++)
		{
			endp[-i] = colonp[n - i];
			colonp[n - i] = 0;
		}
		tp = endp;
	}
	if (tp != endp)
		goto enoent;

	/*
	 * Copy out the result.
	 */
	memcpy(dst, tmp, NS_IN6ADDRSZ);

	return (bits);

enoent:
	errno = ENOENT;
	return (-1);

emsgsize:
	errno = EMSGSIZE;
	return (-1);
}

