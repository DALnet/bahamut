/************************************************************************
 *   IRC - Internet Relay Chat, src/socketengine_select.c
 *   Copyright (C) 2003 Lucas Madar
 *
 * engine functions for the select() socket engine
 *
 */

/* $Id$ */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "fds.h"

static fd_set g_read_set, g_write_set;

void engine_init()
{
   FD_ZERO(&g_read_set);
   FD_ZERO(&g_write_set);
}

void engine_add_fd(int fd)
{
   set_fd_internal(fd, (void *) 0);
}

void engine_del_fd(int fd)
{
   FD_CLR(fd, &g_read_set);
   FD_CLR(fd, &g_write_set);
}

void engine_change_fd_state(int fd, unsigned int stateplus)
{
   int prevstate = (int) get_fd_internal(fd);

   if((stateplus & FDF_WANTREAD) && !(prevstate & FDF_WANTREAD))
   { 
      FD_SET(fd, &g_read_set);
      prevstate |= FDF_WANTREAD;
   }
   else if(!(stateplus & FDF_WANTREAD) && (prevstate & FDF_WANTREAD))
   {
      FD_CLR(fd, &g_read_set);
      prevstate &= ~(FDF_WANTREAD);
   }

   if((stateplus & FDF_WANTWRITE) && !(prevstate & FDF_WANTWRITE))
   {
      FD_SET(fd, &g_write_set);
      prevstate |= FDF_WANTWRITE;
   }
   else if(!(stateplus & FDF_WANTWRITE) && (prevstate & FDF_WANTWRITE))
   {
      FD_CLR(fd, &g_write_set);
      prevstate &= ~(FDF_WANTWRITE);
   }

   set_fd_internal(fd, (void *) prevstate);
}

static void engine_get_fdsets(fd_set *r, fd_set *w)
{
   memcpy(r, &g_read_set, sizeof(fd_set));
   memcpy(w, &g_write_set, sizeof(fd_set));
}

int engine_read_message(time_t delay)
{
   static char errmsg[512];
   fd_set read_set, write_set;
   struct timeval wt;   
   int nfds, length, i;
   unsigned int fdflags;
   int fdtype;
   void *fdvalue;
   aClient *cptr;

   engine_get_fdsets(&read_set, &write_set);

   wt.tv_sec = delay;
   wt.tv_usec = 0;

   nfds = select(MAXCONNECTIONS, &read_set, &write_set, NULL, &wt);
   if (nfds == -1)
   {
      if(((errno == EINTR) || (errno == EAGAIN)))
         return -1;
      report_error("select %s:%s", &me);
      sleep(5);
      return -1;
   }
   else if (nfds == 0)
      return 0;

   if(delay)
      NOW = timeofday = time(NULL);

   for (i = 0; i < MAXCONNECTIONS; i++) 
   {
      get_fd_info(i, &fdtype, &fdflags, &fdvalue);

      cptr = NULL;
      length = -1;

      if (nfds)
      {
         int rr = FD_ISSET(i, &read_set);
         int rw = FD_ISSET(i, &write_set);

         if(rr || rw)
            nfds--;
         else
            continue;

         fdfprintf(stderr, "fd %d: %s%s\n", i, rr ? "read " : "", rw ? "write" : "");

         switch(fdtype)
         {
            case FDT_NONE:
               continue;

            case FDT_AUTH:
               cptr = (aClient *) fdvalue;
               if (rr)
                  read_authports(cptr);
               if (rw && cptr->authfd >= 0)
                  send_authports(cptr);
               check_client_fd(cptr);
               continue;

            case FDT_LISTENER:
               cptr = (aClient *) fdvalue;
               if(rr)
                  accept_connection(cptr);
               continue;

            case FDT_RESOLVER:
               do_dns_async();
               continue;

            case FDT_CLIENT:
               cptr = (aClient *) fdvalue;

               /*
                * NOTE
                *
                * We now do this in a more logical way.
                * We request a write poll on a socket for two reasons
                * - the socket is waiting for a connect() call
                * - the socket is blocked
                */
               if (rw)
               {
                  if (IsConnecting(cptr) && completed_connection(cptr))
                  {
                     ircsprintf(errmsg, "Connect Error: %s", irc_get_sockerr(cptr));
                     exit_client(cptr, cptr, &me, errmsg);
                     continue;
                  }

                  if(cptr->flags & FLAGS_BLOCKED)
                  {
                     cptr->flags &= ~FLAGS_BLOCKED;
                     unset_fd_flags(cptr->fd, FDF_WANTWRITE);
                  }
               }

               length = 1; /* for fall through case */

               if (rr)
                 length = read_packet(cptr);
               else if(DBufLength(&cptr->recvQ) && IsPerson(cptr) && !NoNewLine(cptr))
                 length = do_client_queue(cptr);

               if (length == FLUSH_BUFFER)
                  continue;
	
               if (IsDead(cptr)) 
               {
                  ircsprintf(errmsg, "Read/Dead Error: %s", 
                             (cptr->flags & FLAGS_SENDQEX) ?
                             "SendQ Exceeded" : irc_get_sockerr(cptr));
                  exit_client(cptr, cptr, &me, errmsg);
                  continue;
               }
	
               if (length > 0)
                  continue;
	
               /* An error has occured reading from cptr, drop it. */
               read_error_exit(cptr, length, cptr->sockerr);
               break;

            default:
               abort(); /* unknown client type? bail! */
         }
      }
      else
         break; /* no more fds? break out of the loop */
   } /* end of for() loop for testing selected sockets */

   return 0;
}
