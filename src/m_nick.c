/* m_nick.c - Because s_user.c was just crazy.
 *   Copyright (C) 1990 Jarkko Oikarinen and
 *                      University of Oulu, Computing Center
 *
 *   See file AUTHORS in IRC package for additional names of
 *   the programmers.
 *
 *   This program is free softwmare; you can redistribute it and/or modify
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

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "channel.h"
#include <sys/stat.h>
#include <fcntl.h>
#include "h.h"
#include "userban.h"
#include "hooks.h"

extern int do_user(char *, aClient *, aClient *, char *, char *, char *,
		   unsigned long, char *, char *);

extern int register_user(aClient *, aClient *, char *, char *, char *);
extern int del_dccallow(aClient *, aClient *, int);

extern int is_xflags_exempted(aClient *sptr, aChannel *chptr);
extern int verbose_to_relaychan(aClient *sptr, aChannel *chptr, char *cmd, char *reason);

extern int user_modes[];

/*
 * * 'do_nick_name' ensures that the given parameter (nick) is * really
 * a proper string for a nickname (note, the 'nick' * may be modified
 * in the process...) *
 *
 *      RETURNS the length of the final NICKNAME (0, if *
 * nickname is illegal) *
 *
 *  Nickname characters are in range *  'A'..'}', '_', '-', '0'..'9' *
 * anything outside the above set will terminate nickname. *  In
 * addition, the first character cannot be '-' *  or a Digit. *
 *
 *  Note: *     '~'-character should be allowed, but *  a change should
 * be global, some confusion would *    result if only few servers
 * allowed it...
 */

static int do_nick_name(char *nick) {
  char   *ch;

  if (*nick == '-' || IsDigit(*nick))	/* first character is [0..9-] */
      return 0;

  for (ch = nick; *ch && (ch - nick) < NICKLEN; ch++)
      if (!isvalid(*ch) || IsSpace(*ch))
	  break;

  *ch = '\0';

  return (ch - nick);
}

/*
 * m_nick
 * parv[0] = sender prefix
 * parv[1] = nickname
 * parv[2] = hopcount when new user; TS when nick change
 * parv[3] = TS
 * ---- new user only below ----
 * parv[4] = umode
 * parv[5] = username
 * parv[6] = hostname
 * parv[7] = server
 * parv[8] = serviceid
 * parv[9] = IP
 * parv[10] = ircname
 * -- endif
 */
int m_nick(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    struct simBan *ban;
    aClient    *acptr, *uplink;
    Link       *lp, *lp2;
    char        nick[NICKLEN + 2];
    ts_val      newts = 0;
    int         sameuser = 0, samenick = 0;

    if (parc < 2)
    {
	sendto_one(sptr, err_str(ERR_NONICKNAMEGIVEN),
		   me.name, parv[0]);
	return 0;
    }

    if (!IsServer(sptr) && IsServer(cptr) && parc > 2)
	newts = atol(parv[2]);
    else if (IsServer(sptr) && parc > 3)
	newts = atol(parv[3]);
    else
	parc = 2;
    /*
     * parc == 2 on a normal client sign on (local) and a normal client
     * nick change
     * parc == 4 on a normal server-to-server client nick change
     * parc == 11 on a normal TS style server-to-server NICK introduction
     */
    if ((IsServer(sptr) || (parc > 4)) && (parc < 11))
    {
	/*
	 * We got the wrong number of params. Someone is trying to trick
	 * us. Kill it. -ThemBones As discussed with ThemBones, not much
	 * point to this code now sending a whack of global kills would
	 * also be more annoying then its worth, just note the problem,
	 * and continue -Dianora
	 */
	sendto_realops("IGNORING BAD NICK: %s[%s@%s] on %s (from %s)", parv[1],
		       (parc >= 6) ? parv[5] : "-",
		       (parc >= 7) ? parv[6] : "-",
		       (parc >= 8) ? parv[7] : "-", parv[0]);
	return 0;

    }

    strncpyzt(nick, parv[1], NICKLEN + 1);
    /*
     * if do_nick_name() returns a null name OR if the server sent a
     * nick name and do_nick_name() changed it in some way (due to rules
     * of nick creation) then reject it. If from a server and we reject
     * it, and KILL it. -avalon 4/4/92
     */
    if (do_nick_name(nick) == 0 || (IsServer(cptr) && strcmp(nick, parv[1])))
    {
	sendto_one(sptr, err_str(ERR_ERRONEUSNICKNAME),
		   me.name, parv[0], parv[1], "Erroneous Nickname");

	if (IsServer(cptr))
	{
	    ircstp->is_kill++;
        sendto_realops_lev(DEBUG_LEV, "Bad Nick: %s From: %s Via: %s",
			       parv[1], parv[0],
			       get_client_name(cptr, HIDEME));
	    sendto_one(cptr, ":%s KILL %s :%s (Bad Nick)",
		       me.name, parv[1], me.name);
	    if (sptr != cptr) { /* bad nick change */
		sendto_serv_butone(cptr, ":%s KILL %s :%s (Bad Nick)", me.name,
				   parv[0], me.name);
		sptr->flags |= FLAGS_KILLED;
		return exit_client(cptr, sptr, &me, "BadNick");
	    }
	}
	return 0;
    }
    /*
     * Check against nick name collisions.
     *
     * Put this 'if' here so that the nesting goes nicely on the screen
     * :) We check against server name list before determining if the
     * nickname is present in the nicklist (due to the way the below
     * for loop is constructed). -avalon
     */
    do
    {
	if ((acptr = find_server(nick, NULL)))
	    if (MyConnect(sptr))
	    {
		sendto_one(sptr, err_str(ERR_NICKNAMEINUSE), me.name,
			   BadPtr(parv[0]) ? "*" : parv[0], nick);
		return 0;
	    }

	/*
	 * acptr already has result from find_server
	 * Well. unless we have a capricious server on the net, a nick can
	 * never be the same as a server name - Dianora
	 * That's not the only case; maybe someone broke do_nick_name
	 * or changed it so they could use "." in nicks on their network
	 * - sedition
	 */

	if (acptr)
	{
	    /*
	     * We have a nickname trying to use the same name as a
	     * server. Send out a nick collision KILL to remove the
	     * nickname. As long as only a KILL is sent out, there is no
	     * danger of the server being disconnected.  Ultimate way to
	     * jupiter a nick ? >;-). -avalon
	     */
	    sendto_realops_lev(SKILL_LEV, "Nick collision on %s", sptr->name);
	    ircstp->is_kill++;
	    sendto_one(cptr, ":%s KILL %s :%s (Nick Collision)", me.name,
		       sptr->name, me.name);
	    sptr->flags |= FLAGS_KILLED;
	    return exit_client(cptr, sptr, &me, "Nick/Server collision");
	}

	if (!(acptr = find_client(nick, NULL)))
	    break;

	/*
	 * If acptr == sptr, then we have a client doing a nick change
	 * between *equivalent* nicknames as far as server is concerned
	 * (user is changing the case of his/her nickname or somesuch)
	 */
	if (acptr == sptr)
	{
	    if (strcmp(acptr->name, nick) == 0)
		return 0;
	    else
		break;
	} /* If user is changing nick to itself no point in propogating */

	/*
	 * Note: From this point forward it can be assumed that acptr !=
	 * sptr (point to different client structures).
	 *
	 * If the older one is "non-person", the new entry is just
	 * allowed to overwrite it. Just silently drop non-person, and
	 * proceed with the nick. This should take care of the "dormant
	 * nick" way of generating collisions...
	 */
	if (IsUnknown(acptr))
	{
	    if (MyConnect(acptr))
	    {
		exit_client(NULL, acptr, &me, "Overridden");
		break;
	    }
	    else if (!(acptr->user))
	    {
		sendto_realops_lev(SKILL_LEV, "Nick Collision on %s", parv[1]);
		sendto_serv_butone(NULL, ":%s KILL %s :%s (Nick Collision)",
				   me.name, acptr->name, me.name);
		acptr->flags |= FLAGS_KILLED;
		/* Having no USER struct should be ok... */
		return exit_client(cptr, acptr, &me,
				   "Got TS NICK before Non-TS USER");
	    }
	}

	if (!IsServer(cptr))
	{
	    /*
	     * NICK is coming from local client connection. Just send
	     * error reply and ignore the command.
	     * parv[0] is empty on connecting clients
	     */
	    sendto_one(sptr, err_str(ERR_NICKNAMEINUSE),
		       me.name, BadPtr(parv[0]) ? "*" : parv[0], nick);
	    return 0;
	}
	/*
	 * NICK was coming from a server connection. Means that the same
	 * nick is registered for different users by different server.
	 * This is either a race condition (two users coming online about
	 * same time, or net reconnecting) or just two net fragments
	 * becoming joined and having same nicks in use. We cannot have
	 * TWO users with same nick--purge this NICK from the system with
	 * a KILL... >;)
	 *
	 * Changed to something reasonable like IsServer(sptr) (true if
	 * "NICK new", false if ":old NICK new") -orabidoo
	 */

	if (IsServer(sptr))
	{
	    /*
	     * A new NICK being introduced by a neighbouring server (e.g.
	     * message type "NICK new" received)
	     */
	    if (!newts || !acptr->tsinfo || (newts == acptr->tsinfo))
	    {
		sendto_realops_lev(SKILL_LEV, "Nick collision on %s", parv[1]);
		ircstp->is_kill++;
		sendto_one(acptr, err_str(ERR_NICKCOLLISION),
			   me.name, acptr->name, acptr->name);
		sendto_serv_butone(NULL, ":%s KILL %s :%s (Nick Collision)",
				   me.name, acptr->name, me.name);
		acptr->flags |= FLAGS_KILLED;
		return exit_client(cptr, acptr, &me, "Nick collision");
	    }
	    else
	    {
		/* XXX This looks messed up to me XXX - Raist */
		sameuser = (acptr->user) &&
		    mycmp(acptr->user->username, parv[5]) == 0 &&
		    mycmp(acptr->user->host, parv[6]) == 0;
		if ((sameuser && newts < acptr->tsinfo) ||
		    (!sameuser && newts > acptr->tsinfo))
		{
		    return 0;
		}
		else
		{
		    sendto_realops_lev(SKILL_LEV, "Nick collision on %s",parv[1]);
		    ircstp->is_kill++;
		    sendto_one(acptr, err_str(ERR_NICKCOLLISION),
			       me.name, acptr->name, acptr->name);
		    sendto_serv_butone(sptr, ":%s KILL %s :%s (Nick Collision)",
				       me.name, acptr->name, me.name);
		    acptr->flags |= FLAGS_KILLED;
		    (void) exit_client(cptr, acptr, &me, "Nick collision");
		    break;
		}
	    }
	}
	/*
	 * * A NICK change has collided (e.g. message type * ":old NICK
	 * new". This requires more complex cleanout. * Both clients must be
	 * purged from this server, the "new" * must be killed from the
	 * incoming connection, and "old" must * be purged from all outgoing
	 * connections.
	 */
	if (!newts || !acptr->tsinfo || (newts == acptr->tsinfo) ||
	    !sptr->user)
	{
	    sendto_realops_lev(SKILL_LEV, "Nick change collision: %s", parv[1]);
	    ircstp->is_kill++;
	    sendto_one(acptr, err_str(ERR_NICKCOLLISION),
		       me.name, acptr->name, acptr->name);
	    sendto_serv_butone(NULL, ":%s KILL %s :%s (Nick Collision)",me.name,
			       sptr->name, me.name);
	    ircstp->is_kill++;
	    sendto_serv_butone(NULL, ":%s KILL %s :%s (Nick Collision)",me.name,
			       acptr->name, me.name);
	    acptr->flags |= FLAGS_KILLED;
	    (void) exit_client(NULL, acptr, &me, "Nick collision(new)");
	    sptr->flags |= FLAGS_KILLED;
	    return exit_client(cptr, sptr, &me, "Nick collision(old)");
	}
	else
	{
	    /* XXX This looks messed up XXX */
	    sameuser = mycmp(acptr->user->username, sptr->user->username) == 0
		&& mycmp(acptr->user->host, sptr->user->host) == 0;
	    if ((sameuser && newts < acptr->tsinfo) ||
		(!sameuser && newts > acptr->tsinfo)) {
		if (sameuser)
		    sendto_realops_lev(SKILL_LEV,
				   "Nick change collision from %s to %s",
				   sptr->name, acptr->name);
		ircstp->is_kill++;
		sendto_serv_butone(cptr, ":%s KILL %s :%s (Nick Collision)", me.name,
				   sptr->name, me.name);
		sptr->flags |= FLAGS_KILLED;
		if (sameuser)
		    return exit_client(cptr, sptr, &me, "Nick collision(old)");
		else
		    return exit_client(cptr, sptr, &me, "Nick collision(new)");
	    }
	    else
	    {
		sendto_realops_lev(SKILL_LEV, "Nick collision on %s", acptr->name);

		ircstp->is_kill++;
		sendto_one(acptr, err_str(ERR_NICKCOLLISION),
			   me.name, acptr->name, acptr->name);
		sendto_serv_butone(sptr, ":%s KILL %s :%s (Nick Collision)",me.name,
				   acptr->name, me.name);
		acptr->flags |= FLAGS_KILLED;
		(void) exit_client(cptr, acptr, &me, "Nick collision");
	    }
	}
    } while (0);

    if (IsServer(sptr))
    {
	uplink = find_server(parv[7], NULL);
	if(!uplink)
	{
	    /* if we can't find the server this nick is on,
	     * complain loudly and ignore it. - lucas */
	    sendto_realops("Remote nick %s on UNKNOWN server %s",
			   nick, parv[7]);
	    return 0;
	}
	sptr = make_client(cptr, uplink);

	/* If this is on a U: lined server, it's a U: lined client. */
	if(IsULine(uplink))
	    sptr->flags|=FLAGS_ULINE;

	add_client_to_list(sptr);
	if (parc > 2)
	    sptr->hopcount = atoi(parv[2]);
	if (newts)
	{
	    sptr->tsinfo = newts;
	}
	else
	{
	    newts = sptr->tsinfo = (ts_val) timeofday;
	    ts_warn("Remote nick %s introduced without a TS", nick);
	}
	/* copy the nick in place */
	(void) strcpy(sptr->name, nick);
	(void) add_to_client_hash_table(nick, sptr);
	if (parc >= 10)
	{
	    int *s, flag;
	    char *m;

	    /* parse the usermodes -orabidoo */
	    m = &parv[4][1];
	    while (*m)
	    {
		for (s = user_modes; (flag = *s); s += 2)
		    if (*m == *(s + 1))
		    {
			if ((flag == UMODE_o) || (flag == UMODE_O))
			    Count.oper++;
			sptr->umode |= flag & SEND_UMODES;
			break;
		    }
		m++;
	    }
	    if (parc==10)
	    {
		return do_user(nick, cptr, sptr, parv[5], parv[6],
			       parv[7], strtoul(parv[8], NULL, 0),
			       "0.0.0.0", parv[9]);
	    } else if (parc==11)
	    {
		return do_user(nick, cptr, sptr, parv[5], parv[6], parv[7],
			       strtoul(parv[8], NULL, 0),
			       parv[9], parv[10]);
	    }
	}
    }
    else if (sptr->name[0])
    {
#ifdef DONT_CHECK_QLINE_REMOTE
	if (MyConnect(sptr))
	{
#endif
	    if ((ban = check_mask_simbanned(nick, SBAN_NICK)))
	    {
#ifndef DONT_CHECK_QLINE_REMOTE
		if (!MyConnect(sptr))
		    sendto_realops("Restricted nick %s from %s on %s", nick,
				   (*sptr->name != 0 && !IsServer(sptr)) ?
				   sptr->name : "<unregistered>",
				   (sptr->user == NULL) ? ((IsServer(sptr)) ?
							   parv[6] : me.name) :
				   sptr->user->server);
#endif

		if (MyConnect(sptr) && (!IsServer(cptr)) && (!IsOper(cptr))
		    && (!IsULine(sptr)))
		{
		    sendto_one(sptr, err_str(ERR_ERRONEUSNICKNAME), me.name,
			       BadPtr(parv[0]) ? "*" : parv[0], nick,
			       BadPtr(ban->reason) ? "Erroneous Nickname" :
			       ban->reason);
                    if (call_hooks(CHOOK_FORBID, cptr, nick, ban) != FLUSH_BUFFER)
		        sendto_realops_lev(REJ_LEV,
			    	           "Forbidding restricted nick %s from %s",
				           nick, get_client_name(cptr, FALSE));
		    return 0;
		}
	    }
#ifdef DONT_CHECK_QLINE_REMOTE
	}
#endif
	if (MyConnect(sptr))
	{
	    if (IsRegisteredUser(sptr))
	    {

		/* before we change their nick, make sure they're not banned
		 * on any channels, and!! make sure they're not changing to
		 * a banned nick -sed */
		/* a little cleaner - lucas */

		for (lp = sptr->user->channel; lp; lp = lp->next)
		{
                    if((lp->value.chptr->xflags & XFLAG_NO_NICK_CHANGE) && !is_xflags_exempted(sptr,lp->value.chptr))
                    {
                        if(lp->value.chptr->xflags & XFLAG_USER_VERBOSE)
                            verbose_to_relaychan(sptr, lp->value.chptr, "nick_change", NULL);
                        if(lp->value.chptr->xflags & XFLAG_OPER_VERBOSE)
                            verbose_to_opers(sptr, lp->value.chptr, "nick_change", nick);
			sendto_one(sptr, err_str(ERR_BANNICKCHANGE), me.name,
				   sptr->name, lp->value.chptr->chname);
			return 0;
                    }
		    if (can_send(sptr, lp->value.chptr, NULL))
		    {
			sendto_one(sptr, err_str(ERR_BANNICKCHANGE), me.name,
				   sptr->name, lp->value.chptr->chname);
			return 0;
		    }
		    if (nick_is_banned(lp->value.chptr, nick, sptr) != NULL)
		    {
			sendto_one(sptr, err_str(ERR_BANONCHAN), me.name,
				   sptr->name, nick, lp->value.chptr->chname);
			return 0;
		    }
		}
#ifdef ANTI_NICK_FLOOD
		if ((sptr->last_nick_change + MAX_NICK_TIME) < NOW)
		    sptr->number_of_nick_changes = 0;
		sptr->last_nick_change = NOW;
		sptr->number_of_nick_changes++;

		if (sptr->number_of_nick_changes > MAX_NICK_CHANGES &&
		    !IsAnOper(sptr))
		{
		    sendto_one(sptr,
			       ":%s NOTICE %s :*** Notice -- Too many nick "
			       "changes. Wait %d seconds before trying again.",
			       me.name, sptr->name, MAX_NICK_TIME);
		    return 0;
		}
#endif
		/* If it changed nicks, -r it */
		if ((sptr->umode & UMODE_r) && (mycmp(parv[0], nick) != 0))
		{
		    unsigned int oldumode;
		    char mbuf[BUFSIZE];

		    oldumode = sptr->umode;
		    sptr->umode &= ~UMODE_r;
		    send_umode(sptr, sptr, oldumode, ALL_UMODES, mbuf, sizeof(mbuf));
		}

                /* LOCAL NICKHANGE */
                /*
                 * Client just changing his/her nick. If he/she is on a
                 * channel, send note of change to all clients on that channel.
                 * Propagate notice to other servers.
                 */
                /* if the nickname is different, set the TS */
                if (mycmp(parv[0], nick))
                {
                  sptr->tsinfo = newts ? newts : (ts_val) timeofday;
                }

		sendto_common_channels(sptr, ":%s NICK :%s", parv[0],
				       nick);
		if (sptr->user)
		{
		    add_history(sptr, 1);

		    sendto_serv_butone(cptr, ":%s NICK %s :%ld",
				       parv[0], nick, sptr->tsinfo);
		}
	    }
	}
	else
	{
            /* REMOTE NICKCHANGE */
            /*
             * Client just changing his/her nick. If he/she is on a
             * channel, send note of change to all clients on that channel.
             * Propagate notice to other servers.
             */
            /* if the nickname is different, set the TS */
            if (mycmp(parv[0], nick))
            {
              sptr->tsinfo = newts ? newts : (ts_val) timeofday;
            }

	    sendto_common_channels(sptr, ":%s NICK :%s", parv[0], nick);
	    if (sptr->user)
	    {
		add_history(sptr, 1);

		sendto_serv_butone(cptr, ":%s NICK %s :%ld",
				   parv[0], nick, sptr->tsinfo);
	    }

	    /* If it changed nicks, -r it */
	    if (mycmp(parv[0], nick))
		sptr->umode &= ~UMODE_r;

	    /*
	     * Flush the banserial for the channels the user is in, since this
	     * could be a SVSNICK induced nick change, which overrides any ban
	     * checking on the originating server.
	     */
	    flush_user_banserial(sptr);
	}
        /* Remove dccallow entries for users who don't share common channel(s) unless they only change their nick capitalization -Kobi_S */
        if(sptr->user && mycmp(parv[0], nick))
        {
            for(lp = sptr->user->dccallow; lp; lp = lp2)
            {
                lp2 = lp->next;
                if(lp->flags == DCC_LINK_ME)
                    continue;
                if(!find_shared_chan(sptr, lp->value.cptr))
                {
                    sendto_one(lp->value.cptr, ":%s %d %s :%s has been removed from "
                               "your DCC allow list for signing off",
                               me.name, RPL_DCCINFO, lp->value.cptr->name, parv[0]);
                    del_dccallow(lp->value.cptr, sptr, 1);
                }
            }
        }
    }
    else
    {
	/* Client setting NICK the first time */
	if (MyConnect(sptr))
	{
	    if ((ban = check_mask_simbanned(nick, SBAN_NICK)))
	    {
		if (MyConnect(sptr) && (!IsServer(cptr)) && (!IsOper(cptr))
		    && (!IsULine(sptr)))
		{
		    sendto_one(sptr, err_str(ERR_ERRONEUSNICKNAME), me.name,
			       BadPtr(parv[0]) ? "*" : parv[0], nick,
			       BadPtr(ban->reason) ? "Erroneous Nickname" :
			       ban->reason);
                    if (call_hooks(CHOOK_FORBID, cptr, nick, ban) != FLUSH_BUFFER)
		        sendto_realops_lev(REJ_LEV,
				           "Forbidding restricted nick %s from %s", nick,
				           get_client_name(cptr, FALSE));
		    return 0;
		}
	    }
	}

	strcpy(sptr->name, nick);
	sptr->tsinfo = timeofday;
	if (sptr->user
#ifdef IRCV3
	&& (!stpr->wants_ipv3_caps ||
	(sptr->wants_ipv3_caps && sptr->capabilities))
#endif
	)
	{
	    /*USER already received, and now we have NICK
			* but let's make sure client isn't waiting for CAPAB END
			-skill
			*/

	    if (register_user(cptr, sptr, nick, sptr->user->username, NULL)
		== FLUSH_BUFFER)
		return FLUSH_BUFFER;
	}
    }

    /* Finally set new nick name. */
    if (sptr->name[0])
    {
        del_from_client_hash_table(sptr->name, sptr);
        samenick = mycmp(sptr->name, nick) ? 0 : 1;
        if (IsPerson(sptr))
        {
            if (!samenick)
                hash_check_watch(sptr, RPL_LOGOFF);
#ifdef RWHO_PROBABILITY
            probability_change(sptr->name, nick);
#endif
        }
    }
    strcpy(sptr->name, nick);
    add_to_client_hash_table(nick, sptr);
    if (IsPerson(sptr) && !samenick)
	hash_check_watch(sptr, RPL_LOGON);
    return 0;
}
