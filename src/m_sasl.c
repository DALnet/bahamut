/************************************************************************
 *   IRC - Internet Relay Chat, src/m_sasl.c
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Computing Center
 *
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers.
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

#ifdef IRCV3
#include "config.h"
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "h.h"
#include "ircv3.h"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

#if defined( HAVE_STRING_H )
#include <string.h>
#else
/* older unices don't have strchr/strrchr .. help them out */
#include <strings.h>
#undef strchr
#define strchr index
#endif

// Add this hash table for rate limiting
static SASLRateLimit sasl_ratelimit[HASHSIZE];

// Add these helper functions
static void init_sasl_ratelimit(void)
{
    memset(sasl_ratelimit, 0, sizeof(sasl_ratelimit));
}

static SASLRateLimit *find_sasl_ratelimit(const char *ip)
{
    unsigned int hashv = hash_ip(ip);
    return &sasl_ratelimit[hashv % HASHSIZE];
}

static void check_sasl_ratelimit_expiry(SASLRateLimit *rl, int period)
{
    if (rl->first_attempt && (NOW - rl->first_attempt) >= period) {
        // Reset if period has expired
        rl->first_attempt = 0;
        rl->attempts = 0;
    }
}

static int is_sasl_rate_limited(aClient *cptr)
{
    int max_attempts = sasl_ratelimit_attempts;
    int period = sasl_ratelimit_period;
    
    // Parse rate limit from config
    if (rate_str) {
        char *p = strchr(rate_str, ':');
        if (p) {
            *p = '\0';
            max_attempts = atoi(rate_str);
            period = atoi(p + 1);
            *p = ':';
        }
    }

    SASLRateLimit *rl = find_sasl_ratelimit(cptr->hostip);
    check_sasl_ratelimit_expiry(rl, period);

    // If this is first attempt in current period
    if (rl->attempts == 0) {
        rl->first_attempt = NOW;
        strncpy(rl->ip, cptr->hostip, HOSTIPLEN);
        rl->ip[HOSTIPLEN] = '\0';
    }

    rl->attempts++;

    if (rl->attempts > max_attempts) {
        // Use the existing throttle mechanism
        throttle_force(cptr->hostip);
        return 1;
    }

    return 0;
}

// TODO: Modify m_sasl to handle rate limit failures
int m_sasl(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient *target;
    
    // Only allow SASL messages from U-lined clients
    if (!IsULine(sptr))
        return 0;
        
    if (parc < 4)
        return 0;
        
    target = find_person(parv[2], NULL);
    if (!target)
        return 0;
        
    if (!strcmp(parv[3], "SUCCESS")) {
        // On success, clear rate limit
        SASLRateLimit *rl = find_sasl_ratelimit(target->hostip);
        rl->attempts = 0;
        rl->first_attempt = 0;
        
        sendto_one(target, ":%s SASL %s * S SUCCESS", me.name, target->name);
        //Update SASL state
        target->sasl.state = SASL_STATE_AUTHENTICATED;
        if(!IsRegNick(target)) {
            target->umode |= UMODE_r;
        }
        
    }
    else if (!strcmp(parv[3], "FAILED")) {
        // Failed auth counts against rate limit
        if (is_sasl_rate_limited(target)) {
            sendto_one(target, ":%s FAIL AUTHENTICATE SASL :Too many authentication attempts", me.name);
        } else {
            sendto_one(target, ":%s FAIL AUTHENTICATE SASL :Authentication failed", me.name);
        }
        abort_sasl(target);
    }
    else if (!strcmp(parv[3], "MECH")) {
        // Service is telling us what mechanisms it supports
        // We only support PLAIN for now
        if (strstr(parv[4], "PLAIN")) {
            sendto_one(target, "AUTHENTICATE +");
        } else {
            sendto_one(target, ":%s FAIL AUTHENTICATE SASL :Mechanism not supported", me.name);
            abort_sasl(target);
        }
    }
    
    return 0;
}

void init_sasl()
{
    init_sasl_ratelimit();
}

// Add SASL abort helper
void abort_sasl(aClient *cptr)
{
    if (cptr->sasl.mechanism) {
        MyFree(cptr->sasl.mechanism);
        cptr->sasl.mechanism = NULL;
    }
    cptr->sasl.state = SASL_STATE_FAILED;
}

// Add base64 encoding/decoding functions
static int base64_decode(const char *in, char *out, int maxlen)
{
    BIO *b64, *bmem;
    int len;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf((void *)in, strlen(in));
    bmem = BIO_push(b64, bmem);

    len = BIO_read(bmem, out, maxlen);
    BIO_free_all(bmem);

    return len;
}

static int base64_encode(const unsigned char *in, int len, char *out, int maxlen)
{
    BIO *b64, *bmem;
    BUF_MEM *bptr;

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);

    BIO_write(b64, in, len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    if (bptr->length > maxlen - 1) {
        BIO_free_all(b64);
        return -1;
    }

    memcpy(out, bptr->data, bptr->length);
    out[bptr->length] = '\0';
    BIO_free_all(b64);

    return bptr->length;
}

// TODO: Modify m_authenticate to include rate limiting
int m_authenticate(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    // Check rate limit first
    if (is_sasl_rate_limited(cptr)) {
        sendto_one(sptr, ":%s FAIL AUTHENTICATE SASL :Too many authentication attempts", me.name);
        abort_sasl(sptr);
        return 0;
    }

    if (!sptr->sasl.state) {
        sendto_one(sptr, ":%s FAIL AUTHENTICATE SASL :SASL authentication failed (not started)", me.name);
        return 0;
    }

    if (NOW > sptr->sasl.timeout) {
        abort_sasl(sptr);
        sendto_one(sptr, ":%s FAIL AUTHENTICATE SASL :SASL authentication failed (timed out)", me.name);
        return 0;
    }

    if (parc < 2) {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, sptr->name, "AUTHENTICATE");
        abort_sasl(sptr);
        return 0;
    }

    // If client sends "*", abort authentication
    if (strcmp(parv[1], "*") == 0) {
        abort_sasl(sptr);
        sendto_one(sptr, ":%s FAIL AUTHENTICATE SASL :SASL authentication aborted", me.name);
        return 0;
    }

    // Check if SASL service is available
    if (!aliastab[AII_SL].client) {
        sendto_one(sptr, ":%s FAIL AUTHENTICATE SASL :SASL service unavailable", me.name);
        abort_sasl(sptr);
        return 0;
    }

    // First AUTHENTICATE command should be the mechanism
    if (!sptr->sasl.mechanism) {
        if (strcmp(parv[1], "PLAIN") != 0) {
            sendto_one(sptr, ":%s FAIL AUTHENTICATE SASL :PLAIN is the only supported mechanism", me.name);
            abort_sasl(sptr);
            return 0;
        }
        sptr->sasl.mechanism = strdup("PLAIN");
        sendto_one(sptr, "AUTHENTICATE +");
        return 0;
    }

    // Forward authentication data to service using sendto_alias
    sendto_alias(&aliastab[AII_SL], sptr, "AUTHENTICATE %s %s :%s",
        sptr->uid,  // Unique identifier for the authenticating client
        sptr->sasl.mechanism,
        parv[1]
    );

    // Update SASL state
    sptr->sasl.state = SASL_STATE_STARTED;
    return 0;
}

#endif