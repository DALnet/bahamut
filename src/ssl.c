/************************************************************************
 *   IRC - Internet Relay Chat, src/ssl.c
 *   Copyright (C) 2002 Barnaba Marcello <vjt@azzurra.org>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 1, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *   
 *   SSL functions . . .
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "struct.h"
#include <sys/types.h>
#include "h.h"

#ifdef USE_SSL


#define SAFE_SSL_READ	 1
#define SAFE_SSL_WRITE	 2
#define SAFE_SSL_ACCEPT	 3
#define SAFE_SSL_CONNECT 4

extern int errno;

SSL_CTX *ircdssl_ctx; /* for clients connecing in */
SSL_CTX *serverssl_ctx; /* for connecting to servers */

int ssl_capable = 0;
int mydata_index = 0;

int ssl_init()
{
    FILE *file;

    if(!(file = fopen(IRCDSSL_CPATH,"r")))
    {
        fprintf(stderr, "Can't open %s!\n", IRCDSSL_CPATH);
        return 0;
    }
    fclose(file);

    if(!(file = fopen(IRCDSSL_KPATH,"r")))
    {
        fprintf(stderr, "Can't open %s!\n", IRCDSSL_KPATH);
        return 0;
    }
    fclose(file);

    SSL_load_error_strings();
    SSLeay_add_ssl_algorithms();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ircdssl_ctx = SSL_CTX_new(SSLv23_server_method());
	serverssl_ctx = SSL_CTX_new(SSLv23_client_method());
#else
    ircdssl_ctx = SSL_CTX_new(TLS_server_method());
	serverssl_ctx = SSL_CTX_new(TLS_client_method());
	SSL_CTX_set_min_proto_version(serverssl_ctx, TLS1_2_VERSION);
#endif

    if(!ircdssl_ctx)
    {
	ERR_print_errors_fp(stderr);
	return 0;
    }

	if (!serverssl_ctx)
	{
		ERR_print_errors_fp(stderr);
		return 0;
	}

	SSL_CTX_set_verify(serverssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, ssl_verify_callback);

    if(SSL_CTX_use_certificate_chain_file(ircdssl_ctx, IRCDSSL_CPATH) <= 0)
    {
	ERR_print_errors_fp(stderr);
	SSL_CTX_free(ircdssl_ctx);
	return 0;
    }

    if(SSL_CTX_use_PrivateKey_file(ircdssl_ctx,
		IRCDSSL_KPATH, SSL_FILETYPE_PEM) <= 0)
    {
	ERR_print_errors_fp(stderr);
	SSL_CTX_free(ircdssl_ctx);
	return 0;
    }

    if(!SSL_CTX_check_private_key(ircdssl_ctx))
    {
	fprintf(stderr, "Server certificate does not match Server key");
	SSL_CTX_free(ircdssl_ctx);
	return 0;
    }

    return 1;
}

static void abort_ssl_rehash(int do_errors)
{
    if(do_errors)
    {
		char buf[256];
		unsigned long e;

		while((e = ERR_get_error()))
		{
			ERR_error_string_n(e, buf, sizeof(buf) - 1);
			sendto_realops("SSL ERROR: %s", buf);
		}
    }

	sendto_realops("Aborting SSL rehash due to error(s) detected during rehash. Using current SSL configuration.");

    return;
}

int ssl_rehash()
{
    FILE *file;
	SSL_CTX *temp_ircdssl_ctx;
	SSL_CTX *temp_serverssl_ctx;

    if(!(file = fopen(IRCDSSL_CPATH,"r")))
    {
		sendto_realops("SSL ERROR: Cannot open server certificate file.");
		abort_ssl_rehash(0);

        return 0;
    }
    fclose(file);

    if(!(file = fopen(IRCDSSL_KPATH,"r")))
    {
		sendto_realops("SSL ERROR: Cannot open server key file.");
		abort_ssl_rehash(0);

        return 0;
    }
    fclose(file);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (!(temp_serverssl_ctx = SSL_CTX_new(SSLv23_client_method())))
#else
    if (!(temp_serverssl_ctx = SSL_CTX_new(TLS_client_method())))
#endif
    {
		abort_ssl_rehash(1);

		return 0;
	}

	if (serverssl_ctx) 
	{
		SSL_CTX_free(serverssl_ctx);
	}

	serverssl_ctx = temp_serverssl_ctx;
	SSL_CTX_set_verify(serverssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, ssl_verify_callback);
	SSL_CTX_set_min_proto_version(serverssl_ctx, TLS1_2_VERSION);

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if(!(temp_ircdssl_ctx = SSL_CTX_new(SSLv23_server_method())))
#else
    if(!(temp_ircdssl_ctx = SSL_CTX_new(TLS_server_method())))
#endif
    {
		abort_ssl_rehash(1);

		return 0;
    }

    if(SSL_CTX_use_certificate_chain_file(temp_ircdssl_ctx, IRCDSSL_CPATH) <= 0)
    {
		abort_ssl_rehash(1);
    	if(temp_ircdssl_ctx) {
			SSL_CTX_free(temp_ircdssl_ctx);
		}

		return 0;
    }

    if(SSL_CTX_use_PrivateKey_file(temp_ircdssl_ctx,
		IRCDSSL_KPATH, SSL_FILETYPE_PEM) <= 0)
    {
		abort_ssl_rehash(1);
    	if(temp_ircdssl_ctx) {
			SSL_CTX_free(temp_ircdssl_ctx);
		}

		return 0;
    }

    if(!SSL_CTX_check_private_key(temp_ircdssl_ctx))
    {
		sendto_realops("SSL ERROR: Server certificate does not match server key");
		abort_ssl_rehash(0);
	    if(temp_ircdssl_ctx) {
			SSL_CTX_free(temp_ircdssl_ctx);
		}

		return 0;
    }

    if(ircdssl_ctx) {
		SSL_CTX_free(ircdssl_ctx);
	}

	ircdssl_ctx = temp_ircdssl_ctx;

    return 1;
}

static int fatal_ssl_error(int, int, aClient *);

int safe_ssl_read(aClient *acptr, void *buf, int sz)
{
    int len, ssl_err;

    len = SSL_read(acptr->ssl, buf, sz);
    if (len <= 0)
    {
	switch(ssl_err = SSL_get_error(acptr->ssl, len))
        {
	    case SSL_ERROR_SYSCALL:
		if(errno == EWOULDBLOCK || errno == EAGAIN ||
			errno == EINTR)
                {
	    case SSL_ERROR_WANT_READ:
		    errno = EWOULDBLOCK;
		    return -1;
		}
	    case SSL_ERROR_SSL:
		if(errno == EAGAIN)
		    return -1;
	    default:
		return fatal_ssl_error(ssl_err, SAFE_SSL_READ, acptr);
	}
    }
    return len;
}

int safe_ssl_write(aClient *acptr, const void *buf, int sz)
{
    int len, ssl_err;

    len = SSL_write(acptr->ssl, buf, sz);
    if (len <= 0)
    {
	switch(ssl_err = SSL_get_error(acptr->ssl, len))
        {
	    case SSL_ERROR_SYSCALL:
		if(errno == EWOULDBLOCK || errno == EAGAIN ||
			errno == EINTR)
                {
	    case SSL_ERROR_WANT_WRITE:
	    case SSL_ERROR_WANT_READ:
		    errno = EWOULDBLOCK;
		    return -1;
		}
	    case SSL_ERROR_SSL:
		if(errno == EAGAIN)
		    return -1;
	    default:
		return fatal_ssl_error(ssl_err, SAFE_SSL_WRITE, acptr);
        }
    }
    return len;
}

int safe_ssl_connect(aClient *acptr, int fd)
{
	int ssl_err;
	if ((ssl_err = SSL_connect(acptr->ssl)) <=0)
	{
		switch(ssl_err = SSL_get_error(acptr->ssl, ssl_err))
		{
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_WRITE:
			/* handshake will be completed later .. */
			return 1;
			default:
			return fatal_ssl_error(ssl_err, SAFE_SSL_CONNECT, acptr);

		}
		/* not reached */
		return -1;
	}

	return 1;
}

int safe_ssl_accept(aClient *acptr, int fd)
{

    int ssl_err;

    if((ssl_err = SSL_accept(acptr->ssl)) <= 0)
    {
	switch(ssl_err = SSL_get_error(acptr->ssl, ssl_err))
        {
	    case SSL_ERROR_SYSCALL:
		if(errno == EINTR || errno == EWOULDBLOCK
			|| errno == EAGAIN)
	    case SSL_ERROR_WANT_READ:
	    case SSL_ERROR_WANT_WRITE:
		    /* handshake will be completed later . . */
		    return 1;
	    default:
		return fatal_ssl_error(ssl_err, SAFE_SSL_ACCEPT, acptr);
		
	}
	/* NOTREACHED */
	return -1;
    }
    return 1;
}

int ssl_smart_shutdown(SSL *ssl) {
    char i;
    int rc;

    rc = 0;
    for(i = 0; i < 4; i++)
    {
	if((rc = SSL_shutdown(ssl)))
	    break;
    }

    return rc;
}

static int fatal_ssl_error(int ssl_error, int where, aClient *sptr)
{
    /* don`t alter errno */
    int errtmp = errno;
    char *errstr = strerror(errtmp);
    char *ssl_errstr, *ssl_func;

    switch(where)
    {
	case SAFE_SSL_READ:
	    ssl_func = "SSL_read()";
	    break;
	case SAFE_SSL_WRITE:
	    ssl_func = "SSL_write()";
	    break;
	case SAFE_SSL_ACCEPT:
	    ssl_func = "SSL_accept()";
	    break;
	case SAFE_SSL_CONNECT:
	    ssl_func = "SSL_connect()";
		break;
	default:
	    ssl_func = "undefined SSL func [this is a bug] report to coders@dal.net";
    }

    switch(ssl_error)
    {
    	case SSL_ERROR_NONE:
	    ssl_errstr = "No error";
	    break;
	case SSL_ERROR_SSL:
	    ssl_errstr = "Internal OpenSSL error or protocol error";
	    break;
	case SSL_ERROR_WANT_READ:
	    ssl_errstr = "OpenSSL functions requested a read()";
	    break;
	case SSL_ERROR_WANT_WRITE:
	    ssl_errstr = "OpenSSL functions requested a write()";
	    break;
	case SSL_ERROR_WANT_X509_LOOKUP:
	    ssl_errstr = "OpenSSL requested a X509 lookup which didn`t arrive";
	    break;
	case SSL_ERROR_SYSCALL:
	    ssl_errstr = "Underlying syscall error";
	    break;
	case SSL_ERROR_ZERO_RETURN:
	    ssl_errstr = "Underlying socket operation returned zero";
	    break;
	case SSL_ERROR_WANT_CONNECT:
	    ssl_errstr = "OpenSSL functions wanted a connect()";
	    break;
	default:
	    ssl_errstr = "Unknown OpenSSL error (huh?)";
    }

    if((ssl_error==SSL_ERROR_SYSCALL || ssl_error==SSL_ERROR_ZERO_RETURN) && errtmp==0)
    {
        /* Client most likely just closed the connection... -Kobi_S. */
        errno = 0; /* Not really an error */
        sptr->sockerr = IRCERR_SSL;
        sptr->flags |= FLAGS_DEADSOCKET;
        return -1;
    }

    sendto_realops_lev(DEBUG_LEV, "%s to "
		"%s!%s@%s aborted with%serror (%s). [%s]", 
		ssl_func, *sptr->name ? sptr->name : "<unknown>",
		(sptr->user && sptr->user->username) ? sptr->user->
		username : "<unregistered>", sptr->sockhost,
		(errno > 0) ? " " : " no ", errstr, ssl_errstr);
#ifdef USE_SYSLOG
    syslog(LOG_ERR, "SSL error in %s for %s!%s@%s: %s [%s]", ssl_func,
            *sptr->name ? sptr->name : "<unknown>",
            (sptr->user && sptr->user->username) ? sptr->user->
            username : "<unregistered>", sptr->sockhost,
            errstr, ssl_errstr);
#endif

    /* if we reply() something here, we might just trigger another
     * fatal_ssl_error() call and loop until a stack overflow... 
     * the client won`t get the ERROR : ... string, but this is
     * the only way to do it.
     * IRC protocol wasn`t SSL enabled .. --vjt
     */

    errno = errtmp ? errtmp : EIO; /* Stick a generic I/O error */
    sptr->sockerr = IRCERR_SSL;
    sptr->flags |= FLAGS_DEADSOCKET;
    return -1;
}

int ssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	char buf[256];
	X509 *cert;
	SSL *ssl;
	int err, depth;
	aConnect *conn;

    /* 
	 * Retrieve pointer to SSL object to be able to retrieve aConn data.
	 * aConn data is passed during SSL connection to validate subject name matches
	 * aConn->name
	 */

    ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	conn = SSL_get_ex_data(ssl, mydata_index);
    cert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

    X509_NAME_oneline(X509_get_subject_name(cert), buf, 256);
	sendto_realops_lev(DEBUG_LEV, "Got subject name [%d]: %s", depth, buf);


    /*
	 * If initial verification failed, we fail
	 */
    if (!preverify_ok && err != X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) 
	{
		sendto_realops_lev(DEBUG_LEV, "SSL: verify error:num=%d:%s:depth=%d:%s\n", err,
                X509_verify_cert_error_string(err), depth, buf);
		return preverify_ok;
	} else {
		/*
		 * for testing, must delete
		 */
		X509_NAME *subj = X509_get_subject_name(cert);
		for (int i = 0; i < X509_NAME_entry_count(subj); i++) {
			X509_NAME_ENTRY *e = X509_NAME_get_entry(subj, i);
			ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
			char *str = ASN1_STRING_data(d);
			sendto_realops_lev(DEBUG_LEV, "SSL: Entry %d - %s", i, str);
		}
		 if (mycmp(buf, conn->name))
		 {
			 sendto_realops_lev(DEBUG_LEV, "SSL: Valid certificate for %s", conn->name);
			 return 1;
		 } else {
			 sendto_realops_lev(DEBUG_LEV, "SSL: Subject and connection name mismatch %s : %s", buf, conn->name);
			 return preverify_ok;
		 }
	 }
}
#endif
