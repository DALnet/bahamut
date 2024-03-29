/************************************************************************
 *   IRC - Internet Relay Chat, src/dh.c
 *   Copyright (C) 2000 Lucas Madar
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
 */

/*
 * Diffie-Hellman key exchange for bahamut ircd.
 * Lucas Madar <lucas@dal.net> -- 2000
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include "libcrypto-compat.h"

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

#include "memcount.h"

#define DH_HEADER
#include "dh.h"


#ifdef __OpenBSD__
#define RAND_SRC "/dev/arandom"
#else
#ifdef __linux__
#define RAND_SRC "/dev/urandom"
#else
#define RAND_SRC "/dev/urandom"
#endif
#endif


static int verify_is_hex(char *string)
{
    int l = strlen(string);
    char tmp[4] = {'\0', '\0', '\0', '\0'};
    int tmpidx = 0;

    if(l & 0x01) /* check if it's odd length */
    {  
        l++;
        tmp[tmpidx++] = '0'; /* pad with zero */
    }
   
    while(*string)
    {
        tmp[tmpidx++] = *string++;
        if(tmpidx == 2)
        {
            char *eptr;

            tmpidx = 0;

            (void) strtol(tmp, &eptr, 16);
            if(*eptr != '\0')
                return 0;
        }
    }
    return 1;
}

int dh_hexstr_to_raw(char *string, unsigned char *hexout, int *hexlen)
{
    int l = strlen(string);
    char tmp[3] = {'\0', '\0', '\0'};
    int tmpidx = 0;
    int hexidx = 0;

    if(l & 0x01) /* check if it's odd length */
    {  
        l++;
        tmp[tmpidx++] = '0'; /* pad with zero */
    }
   
    while(*string)
    {
        tmp[tmpidx++] = *string++;
        if(tmpidx == 2)
        {
            char *eptr;
            unsigned char x;
   
            tmpidx = 0;
   
            x = strtol(tmp, &eptr, 16);
            if(*eptr != '\0')
                return 0;
            hexout[hexidx++] = (unsigned char) x;
        }
    }
    *hexlen = hexidx;
    return 1;
}

static inline void entropy_error(void)
{
    printf("\nCould not generate entropy from %s:\n%s\n\n",
           RAND_SRC, strerror(errno));
    printf("ircd needs a %d byte random seed.\n", RAND_BYTES);
    printf("You can place a file containing random data called"
           " .ircd.entropy\nin the directory with your ircd.conf."
           " This file must be at least %d bytes\n", RAND_BYTES);
    printf("long and should be suitably random.\n");
}

static int make_entropy()
{
    char randbuf[RAND_BYTES * 4];
    FILE *fp;
    int i;

    printf("\nNo random state found, generating entropy from %s...\n",
           RAND_SRC);
    printf("On some systems this may take a while, and can be helped by"
           " keeping the\nsystem busy, such as pounding on the keyboard.\n");

    fp = fopen(RAND_SRC, "r");
    if(!fp)
    {
        entropy_error();
        return 0;
    }

    for(i = 0; i < (RAND_BYTES * 4); i++)
    {
        int cv;

        cv = fgetc(fp);

        if(cv == EOF)
        {
            if(ferror(fp))
            {
                entropy_error();
                fclose(fp);
                return 0;
            }
            clearerr(fp);
            usleep(100);
            i--;
            continue;
        }

        randbuf[i] = cv;
        if(i && (i % 64 == 0))
        {
            printf(" %d%% .. ", (int)(((float) i / (float) (RAND_BYTES * 4)) 
                    * 100.0));
            fflush(stdout);
        }
    }
    printf("Done.\n");
    fclose(fp);

    fp = fopen(".ircd.entropy", "w");
    if(!fp)
    {
        printf("Could not open .ircd.entropy for writing: %s\n", 
                strerror(errno));
        return 0;
    }

    fwrite(randbuf, RAND_BYTES * 4, 1, fp);
    fclose(fp);

    RAND_load_file(".ircd.entropy", -1);

    return 1;
}

static int init_random()
{
    int ret;
    time_t now;

    ret = RAND_load_file(".ircd.entropy", -1);
    if(ret <= 0)
    {
        if(!make_entropy())
            return -1;
    }
    else
        printf("%d bytes of entropy loaded.\n", ret);

    now = time(NULL);   

    /* this is probably not too good, but it saves just writing
       the whole state back to disk with no changes. */
    RAND_seed(&now, 4); 
    RAND_write_file(".ircd.entropy");

    return 0;
}

static int create_prime()
{
    char buf[PRIME_BYTES_HEX];
    int i;
    int bufpos = 0;

    for(i = 0; i < PRIME_BYTES; i++)
    {
        char *x = dh_hex_to_string[dh_prime_1024[i]];
        while(*x)
            buf[bufpos++] = *x++;
    }
    buf[bufpos] = '\0';

    ircd_prime = NULL;
    BN_hex2bn(&ircd_prime, buf);
    ircd_generator = BN_new();
    BN_set_word(ircd_generator, dh_gen_1024);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PARAM_BLD *paramBuild = NULL;
    OSSL_PARAM *param = NULL;
    EVP_PKEY_CTX *primeCtx = NULL;

    if(!(paramBuild = OSSL_PARAM_BLD_new()) ||
       !OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_P, ircd_prime) ||
       !OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_G, ircd_generator) ||
       !(param = OSSL_PARAM_BLD_to_param(paramBuild)) ||
       !(primeCtx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", NULL)) ||
       EVP_PKEY_fromdata_init(primeCtx) <= 0 ||
       EVP_PKEY_fromdata(primeCtx, &ircd_prime_ossl3,
                         EVP_PKEY_KEY_PARAMETERS, param) <= 0 ||
       1)
    {
        if(primeCtx)
            EVP_PKEY_CTX_free(primeCtx);
        if(param)
            OSSL_PARAM_free(param);
        if(paramBuild)
            OSSL_PARAM_BLD_free(paramBuild);
    }

    if(!ircd_prime_ossl3)
        return -1;
#endif
    return 0;
}

int dh_init()
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    ERR_load_crypto_strings();
#endif

    if(create_prime() == -1 || init_random() == -1)
        return -1;
    return 0; 
}

int dh_generate_shared(void *session, char *public_key)
{
    BIGNUM *tmp;
    size_t len;
    struct session_info *si = (struct session_info *) session;

    if(verify_is_hex(public_key) == 0 || !si || si->session_shared)
        return 0;

    tmp = NULL;
    BN_hex2bn(&tmp, public_key);
    if(!tmp)
        return 0;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    si->session_shared_length = DH_size(si->dh);
    si->session_shared = (unsigned char *) malloc(DH_size(si->dh));
    len = DH_compute_key(si->session_shared, tmp, si->dh);
#else
    OSSL_PARAM_BLD *paramBuild = NULL;
    OSSL_PARAM *param = NULL;
    EVP_PKEY_CTX *peerPubKeyCtx = NULL;
    EVP_PKEY *peerPubKey = NULL;
    EVP_PKEY_CTX *deriveCtx = NULL;

    len = -1;
    if(!(paramBuild = OSSL_PARAM_BLD_new()) ||
       !OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_P, ircd_prime) ||
       !OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_FFC_G, ircd_generator) ||
       !OSSL_PARAM_BLD_push_BN(paramBuild, OSSL_PKEY_PARAM_PUB_KEY, tmp) ||
       !(param = OSSL_PARAM_BLD_to_param(paramBuild)) ||
       !(peerPubKeyCtx = EVP_PKEY_CTX_new_from_name(NULL, "DHX", NULL)) ||
       EVP_PKEY_fromdata_init(peerPubKeyCtx) <= 0 ||
       EVP_PKEY_fromdata(peerPubKeyCtx, &peerPubKey,
                         EVP_PKEY_PUBLIC_KEY, param) <= 0 ||
       !(deriveCtx = EVP_PKEY_CTX_new(si->dh, NULL)) ||
       EVP_PKEY_derive_init(deriveCtx) <= 0 ||
       EVP_PKEY_derive_set_peer(deriveCtx, peerPubKey) <= 0 ||
       EVP_PKEY_derive(deriveCtx, NULL, &len) <= 0 ||
       !(si->session_shared = malloc(len)) ||
       EVP_PKEY_derive(deriveCtx, si->session_shared, &len) <= 0 ||
       1)
    {
        if(deriveCtx)
            EVP_PKEY_CTX_free(deriveCtx);
        if(peerPubKey)
            EVP_PKEY_free(peerPubKey);
        if(peerPubKeyCtx)
            EVP_PKEY_CTX_free(peerPubKeyCtx);
        if(param)
            OSSL_PARAM_free(param);
        if(paramBuild)
            OSSL_PARAM_BLD_free(paramBuild);
    }
#endif
    BN_free(tmp);

    if(len == -1 || !si->session_shared)
    {
        if(si->session_shared)
            free(si->session_shared);
        return 0;
    }

    si->session_shared_length = len;

    return 1;
}

void *dh_start_session()
{
    struct session_info *si;

    si = (struct session_info *) MyMalloc(sizeof(struct session_info));
    if(!si) 
        abort();

    memset(si, 0, sizeof(struct session_info));

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    si->dh = DH_new();
	if(si->dh == NULL)
		return NULL;

	BIGNUM *dhp_bn, *dhg_bn;
	dhp_bn = BN_dup(ircd_prime);
	dhg_bn = BN_dup(ircd_generator);
	if(dhp_bn == NULL || dhg_bn == NULL || !DH_set0_pqg(si->dh, dhp_bn, NULL, dhg_bn)) {
		DH_free(si->dh);
		BN_free(dhp_bn);
		BN_free(dhg_bn);
		return NULL;
	}

    if(!DH_generate_key(si->dh))
    {
        DH_free(si->dh);
        MyFree(si);
        return NULL;
    }
#else
    EVP_PKEY_CTX *keyGenCtx = NULL;

    if(!(keyGenCtx = EVP_PKEY_CTX_new_from_pkey(NULL, ircd_prime_ossl3, NULL)) ||
        EVP_PKEY_keygen_init(keyGenCtx) <= 0 ||
        EVP_PKEY_generate(keyGenCtx, &si->dh) <= 0 ||
        1)
    {
        if(keyGenCtx)
            EVP_PKEY_CTX_free(keyGenCtx);
    }
    if(!si->dh)
    {
        MyFree(si);
        return NULL;
    }
#endif
    return (void *) si;
}

void dh_end_session(void *session)
{
    struct session_info *si = (struct session_info *) session;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if(si->dh)
    {
        DH_free(si->dh);
        si->dh = NULL;
    }

    if(si->session_shared)
    {
        memset(si->session_shared, 0, si->session_shared_length);
        free(si->session_shared);
        si->session_shared = NULL;
    }
#else
    if(si->dh)
    {
        EVP_PKEY_free(si->dh);
        si->dh = NULL;
    }
#endif

    MyFree(si);
}

char *dh_get_s_public(char *buf, size_t maxlen, void *session)
{
    struct session_info *si = (struct session_info *) session;
    char *tmp;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    if(!si || !si->dh)
		return NULL;

	const BIGNUM *pub_key;
	const BIGNUM *priv_key;
	DH_get0_key(si->dh, &pub_key, &priv_key);
	if(pub_key == NULL || priv_key == NULL)
		return NULL;

	tmp = BN_bn2hex(pub_key);
#else
    BIGNUM *pub_key = NULL;

    if(!si || !si->dh)
        return NULL;
    if(!EVP_PKEY_get_bn_param(si->dh, OSSL_PKEY_PARAM_PUB_KEY, &pub_key))
        return NULL;
    tmp = BN_bn2hex(pub_key);
    BN_free(pub_key);
#endif
    if(!tmp)
        return NULL;

    if(strlen(tmp) + 1 > maxlen)
    {
        OPENSSL_free(tmp);
        return NULL;
    }
    strcpy(buf, tmp);
    OPENSSL_free(tmp);

    return buf;
}

int dh_get_s_shared(unsigned char *buf, size_t *maxlen, void *session)
{
    struct session_info *si = (struct session_info *) session;

    if(!si || !si->session_shared || *maxlen < si->session_shared_length)
        return 0;

    *maxlen = si->session_shared_length;
    memcpy(buf, si->session_shared, *maxlen);

    return 1;
}

u_long
memcount_dh(MCdh *mc)
{
    mc->file = __FILE__;

    mc->m_dhsession_size = sizeof(struct session_info);

    return 0;
}
