/************************************************************************
 *   IRC - Internet Relay Chat, src/s_ircv3.c
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

#include "config.h"
#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "h.h"
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

#ifdef IRCV3
#include "ircv3.h"


int cap_set(aClient *, long);
int cap_unset(aClient *, long);


// Add this structure to track rate limits
typedef struct {
    char ip[HOSTIPLEN + 1];
    time_t first_attempt;
    int attempts;
} SASLRateLimit;

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

/*
 * m_cap
 * IRCv3 support for capability negotiation
 * We will only support the LS, REQ and END subcommands.
 * Plans are to fully add cap-notify capability - skill
 */
int
m_cap(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int         i;

    /* If it's not local, or it has already set capabilities,
     * silently ignore it.
     * Dont ignore clients where we have set some capabilities already
     * that would suck for connecting TO servers.
     */

    if(cptr != sptr)
        return 0;

    if (parc < 2)
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name, sptr->name, "CAP");
        return 0;
    }
    /* Only clients will be sending us IRCv3 CAPAB subcommands */
    if (!IsServer(cptr))
    {
      if (strcmp(parv[1], "LS") == 0)
      {
        /* If we currently support no IRCv3 capabilities, return nothing */
        if (ircv3_capabilities && ircv3_capabilities[0].name)
        {
          char buf[BUFSIZE];
          memset(buf, 0, sizeof(buf));

          for (i = 0; ircv3_capabilities[i].name; i++)
          {
            strcat(buf, ircv3_capabilities[i].name);
            if (ircv3_capabilities[i + 1].name)
              strncat(buf, " ", 1);
          }
          strcat(buf, " sasl");

          /* We identify the client as wanting IRCv3 capabilities
           * so that we only call register_user after CAPAB END is received
          */
         sptr->wants_ircv3_caps = 1;

         sendto_one(sptr, ":%s CAP * LS :%s", me.name, buf);
        }
      }
      else if (strcmp(parv[1], "REQ") == 0)
      {
        char buf[BUFSIZE];
        char smbcmd[3] = "ACK";

        memset(buf, 0, sizeof(buf));

        if (strstr(parv[2], "sasl")) {
            sptr->sasl.state = 1;
            sptr->sasl.timeout = NOW + SASL_Timeout;
            sptr->sasl.mechanism = NULL;
        }

        for (i = 2; i < parc; i++)
        {
          int add = 1;

          if (parv[i][0] == '-')
          {
            add = 0;
          }

          Debug((DEBUG_DEBUG, "CAP REQ: %s", parv[i]));
          for (int j = 0; ircv3_capabilities[j].name; j++)
          {
            if (strcmp(parv[i], ircv3_capabilities[j].name) == 0)
            {
              if (add)
              {
                if (!cap_set(sptr, ircv3_capabilities[j].capability))
                {
                  strcat(buf, ircv3_capabilities[j].name);

                } else {
                  Debug((DEBUG_DEBUG, "CAP REQ: %s not supported", parv[i]));
                  strcpy(smbcmd, "NAK");
                  strcat(buf, ircv3_capabilities[j].name);
                }
              } else {
                cap_unset(sptr, ircv3_capabilities[j].capability);
                strcat(buf, ircv3_capabilities[j].name);
              }

              if (i < parc - 1)
                strncat(buf, " ", 1);

              break;
            }
          }
        }

        sendto_one(sptr, ":%s CAP * %s :%s", me.name, smbcmd, buf);
      }
      else if (strcmp(parv[1], "END") == 0)
      {
        /* End capabilities negotiation, register user now
        * but only if NICK and USER were already received. If not,
        * we will let those commands handle it - skill
        */
        if (sptr->name[0] && sptr->user && sptr->user->username[0])
          return register_user(cptr, sptr, sptr->name, sptr->user->username, sptr->hostip);
      }
    } else {
      sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, "CAP");
    }

    return 0;
}

/*
 * cap_set
 * Set an IRCV3 capability for a client
*/
int cap_set(aClient *cptr, unsigned int capability)
{
  int set = 0;
  if (cptr->wants_ircv3_caps)
  {
    int i = 0;
    for (i = 0; ircv3_capabilities[i].name; i++)
    {
      if (ircv3_capabilities[i].capability == capability)
      {
        cptr->capabilities |= capability;
        set = 1;
        break;
      }
    }
  }

  return set;
}
/*
  * cap_unset
  * Unset an IRCV3 capability for a client
*/
int cap_unset(aClient *cptr, unsigned int capability)
{
  if (cptr->wants_ircv3_caps)
  {
    for (int i = 0; ircv3_capabilities[i].name; i++)
    {
      if (ircv3_capabilities[i].capability == capability)
      {
        cptr->capabilities &= ~capability;
        break;
      }
    }
  }

  return 0;
}

/*
 * These methods allow the registration of different IRCv3 capabilities and the selection of what
 * IRC messages they want to support. - skill
*/

int ircv3_hook(enum c_ircv3_hooktype hooktype, ...)
{
    va_list vl;
    int ret = 0;


    va_start(vl, hooktype);

    switch(hooktype)
    {
        case IRCV3_HOOK_AWAYNOTIFY_AWAY:
                aClient *cptr = va_arg(vl, aClient *);
                aClient *sptr = va_arg(vl, aClient *);
                char    *message = va_arg(vl, char *);

                for (int i = 0; ircv3_capabilities[i].name; i++)
                {
                    if (ircv3_capabilities[i].capability == CAPAB_AWAYNOTIFY)
                    {
                        int (*rfunc) (aClient *, aClient *, char *) = ircv3_capabilities[i].func;
                        if ((ret = (*rfunc)(cptr, sptr, message)) == FLUSH_BUFFER)
                            break;
                    }
                }
                break;
        case IRCV3_HOOK_AWAYNOTIFY_BACK:
                aClient *cptr = va_arg(vl, aClient *);
                aClient *sptr = va_arg(vl, aClient *);

                for (int i = 0; ircv3_capabilities[i].name; i++)
                {
                    if (ircv3_capabilities[i].capability == CAPAB_AWAYNOTIFY)
                    {
                        int (*rfunc) (aClient *, aClient *, char *) = ircv3_capabilities[i].func;
                        if ((ret = (*rfunc)(cptr, sptr, NULL)) == FLUSH_BUFFER)
                            break;
                    }
                }
                break;

        default:
          sendto_realops_lev(DEBUG_LEV, "Call for unknown hook type %d",
                hooktype);
            break;

    }

    va_end(vl);

    return ret;
}

typedef struct HashEntry {
    aClient *client;
    struct HashEntry *next;
    // Possibly other members...
} HashEntry;

unsigned int hash_nick(const char *name, unsigned int size)
{
    unsigned int hash = 0;

    while (*name)
    {
        hash = (hash * 33) + (unsigned char)*name++;
    }

    return hash % size;
}

// ... existing code ...
// Check if a client has been notified
static inline int IsNotified(HashEntry *notified_clients, aClient *acptr)
{
    unsigned int hashv = hash_nick(acptr->name, HASHSIZE);
    HashEntry *hptr = &notified_clients[hashv];

    while (hptr)
    {
        if (hptr->client == acptr)
            return 1;
        hptr = hptr->next;
    }
    return 0;
}

// Mark a client as notified
static inline void SetNotified(HashEntry *notified_clients, aClient *acptr)
{
    unsigned int hashv = hash_nick(acptr->name, HASHSIZE);
    HashEntry *hptr = &notified_clients[hashv];

    while (hptr->client && hptr->next)
        hptr = hptr->next;

    if (!hptr->client)
        hptr->client = acptr;
    else
    {
        hptr->next = (HashEntry *)MyMalloc(sizeof(HashEntry));
        hptr->next->client = acptr;
        hptr->next->next = NULL;
    }
}

// Clear the notified clients list
static inline void ClearNotifiedList(HashEntry *notified_clients)
{
    for (int i = 0; i < HASHSIZE; i++)
    {
        HashEntry *current = notified_clients[i].next;
        while (current)
        {
            HashEntry *temp = current;
            current = current->next;
            MyFree(temp);
        }
        notified_clients[i].client = NULL;
        notified_clients[i].next = NULL;
    }
}



/*
 * Below section will be to register the methods used to handle the different IRC messages
 * we want to extend IRCv3 capabilites for
*/

/*
 * m_awaynotify
 * Handle the IRCv3 away-notify capability, this is used to notify clients when a user goes
 * away or returns from away. Also, notify channel if user joins with away message set.
 *
 * I can't think of any other way to do this besides iterating through all the channels
 * the user is in and notifying the members. This is ugly, while it saves on bandwidth
 * since clients don't have to do /WHO on join, it's still noisy just like NICK/USER commands. - skill
 * TODO: Find a better way. - skill (2024-07-28)
 * Params:
 *  cptr - The client that is sending the message
 *  sptr - The client that is receiving the message
 *  away - The away message
*/
int m_awaynotify(aClient *cptr, aClient *sptr, char *away)
{
    Link *lp;
    aClient *acptr;
    int fd;

    // Prepare the AWAY message once
    char away_msg[BUFSIZE];
    if (away)
        snprintf(away_msg, sizeof(away_msg), ":%s!%s@%s AWAY :%s",
                 sptr->name, sptr->user->username, sptr->user->host, away);
    else
        snprintf(away_msg, sizeof(away_msg), ":%s!%s@%s AWAY",
                 sptr->name, sptr->user->username, sptr->user->host);

    // Create a temporary hash table to track notified clients
    HashEntry notified_clients[HASHSIZE];
    memset(notified_clients, 0, sizeof(notified_clients));

    // Iterate through all channels the client is a member of
    for (lp = sptr->user->channel; lp; lp = lp->next)
    {
        aChannel *chptr = lp->value.chptr;

        // Iterate through all members of the channel
        for (fd = 0; fd <= highest_fd; fd++)
        {
            if (!(acptr = local[fd]) || !IsRegistered(acptr) || acptr == sptr)
                continue;

            if (IsMember(acptr, chptr) && !IsNotified(notified_clients, acptr))
            {
                if (HasCapability(acptr, CAPAB_AWAYNOTIFY))
                {
                    sendto_one(acptr, "%s", away_msg);
                }
                SetNotified(notified_clients, acptr);
            }
        }
    }
    // Clear the notified clients list
    ClearNotifiedList(notified_clients);

    return 0;
}

// Modify m_authenticate to include rate limiting
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

    return 0;
}

// Modify m_sasl to handle rate limit failures
int m_sasl(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    aClient *target;
    
    // Only allow SASL messages from U-lined clients
    if (!IsULine(sptr))
        return 0;
        
    if (parc < 4)
        return 0;
        
    target = find_uid(parv[2]);
    if (!target)
        return 0;
        
    if (!strcmp(parv[3], "SUCCESS")) {
        // On success, clear rate limit
        SASLRateLimit *rl = find_sasl_ratelimit(target->hostip);
        rl->attempts = 0;
        rl->first_attempt = 0;
        
        sendto_one(target, ":%s SASL %s * S SUCCESS", me.name, target->name);
        target->sasl.state = 0;
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
    cptr->sasl.state = 0;
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

#endif //IRCV3