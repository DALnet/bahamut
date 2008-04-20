#if !defined( DEFS_H_INCLUDED )
# define DEFS_H_INCLUDED 1

/*
 * None of the following should need to be changed by hand.  
 */

# if !defined( HAVE_BCOPY )
#	define bcopy(a,b,c) memcpy(b,a,c)
# endif
# if !defined( HAVE_BCMP )
#	define bcmp memcmp
# endif
# if !defined( HAVE_BZERO )
#	define bzero(a,b) memset(a,0,b)
# endif

# if defined( __osf__ )
#	define OSF
#	undef BSD
#	include <sys/param.h>
#	if !defined( BSD )
#	 define BSD
#	endif
# endif

# if !defined(HAVE_DN_SKIPNAME)
#	if defined(HAVE___DN_SKIPNAME)
#	 define dn_skipname __dn_skipname
#	else
#	error Could not find dn_skipname() or __dn_skipname()
# endif
#endif
/*
 * The following OS specific stuff is a compatibility kludge it would
 * be nice to get rid of all of this eventually.
 */
#if defined(OS_SOLARIS2) && !defined( SOL20 )
# define SOL20 1
#endif

#if defined( aix ) || defined( OS_AIX )
# include <sys/machine.h>
# if BYTE_ORDER == BIG_ENDIAN
#	define BIT_ZERO_ON_LEFT
# elif BYTE_ORDER == LOTTLE_ENDIAN
#	define BIT_ZERO_ON_RIGHT
# endif
# define BSD_INCLUDES
# if !defined( AIX )
#	define AIX 1
# endif
# define USE_POLL 1		/* KLUGE - only define on AIX 4.x!! -cab */
#endif

#if defined( OS_MIPS )
# undef SYSV
# undef BSD
# define BSD 1			/* mips only works in a bsd43 environment */
# if !defined( MIPS )
#	define MIPS 1
# endif
#endif

/* This code contributed by Rossi 'vejeta' Marcello <vjt@users.sourceforge.net>
 * Originally in va_copy.h, however there wasnt much there, so i stuck it in
 * here.  Thanks Rossi!  -epi
 */

/* va_copy hooks for IRCd */

#if defined(__powerpc__)
# if defined(__NetBSD__)
#  define VA_COPY va_copy
# elif defined(__FreeBSD__) || defined(__linux__)
#  define VA_COPY __va_copy
# endif
#elif defined (__x86_64)
# define VA_COPY __va_copy
#else
# define VA_COPY(x, y) x = y
#endif


#endif				/* DEFS_H_INCLUDED */
