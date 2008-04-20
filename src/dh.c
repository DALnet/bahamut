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

/* $Id: dh.c 1303 2006-12-07 03:23:17Z epiphani $ */

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

#include "memcount.h"

#define DH_HEADER
#include "dh.h"


#ifdef __OpenBSD__
#define RAND_SRC "/dev/arandom"
#else
#define RAND_SRC "/dev/random"
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
            unsigned char x;
   
            tmpidx = 0;
   
            x = strtol(tmp, &eptr, 16);
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

static void create_prime()
{
    char buf[PRIME_BYTES_HEX];
    int i;
    int bufpos = 0;

    for(i = 0; i < PRIME_BYTES; i++)
    {
        char *x = hex_to_string[dh_prime_1024[i]];
        while(*x)
            buf[bufpos++] = *x++;
    }
    buf[bufpos] = '\0';

    ircd_prime = NULL;
    BN_hex2bn(&ircd_prime, buf);
    ircd_generator = BN_new();
    BN_set_word(ircd_generator, dh_gen_1024);
}

int dh_init()
{
    ERR_load_crypto_strings();

    create_prime();
    if(init_random() == -1)
        return -1;
    return 0; 
}

int dh_generate_shared(void *session, char *public_key)
{
    BIGNUM *tmp;
    int len;
    struct session_info *si = (struct session_info *) session;

    if(verify_is_hex(public_key) == 0 || !si || si->session_shared)
        return 0;

    tmp = NULL;
    BN_hex2bn(&tmp, public_key);
    if(!tmp)
        return 0;

    si->session_shared_length = DH_size(si->dh);
    si->session_shared = (char *) malloc(DH_size(si->dh));
    len = DH_compute_key(si->session_shared, tmp, si->dh);
    BN_free(tmp);

    if(len < 0)
        return 0;

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

    si->dh = DH_new();
    si->dh->p = BN_dup(ircd_prime);
    si->dh->g = BN_dup(ircd_generator);

    if(!DH_generate_key(si->dh))
    {
        DH_free(si->dh);
        MyFree(si);
        return NULL;
    }

    return (void *) si;
}

void dh_end_session(void *session)
{
    struct session_info *si = (struct session_info *) session;

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

    MyFree(si);
}

char *dh_get_s_public(char *buf, int maxlen, void *session)
{
    struct session_info *si = (struct session_info *) session;
    char *tmp;

    if(!si || !si->dh || !si->dh->pub_key)
        return NULL;   

    tmp = BN_bn2hex(si->dh->pub_key);
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

int dh_get_s_shared(char *buf, int *maxlen, void *session)
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

