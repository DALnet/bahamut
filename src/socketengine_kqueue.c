/************************************************************************
 *   IRC - Internet Relay Chat, src/socketengine_kqueue.c
 *   Copyright (C) 2003 Lucas Madar
 *
 * engine functions for the kqueue() socket engine
 *
 */

/* $Id$ */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "fds.h"

#include <sys/event.h>
#include <sys/time.h>

#define MAX_EVENT_QUEUE 64

static int kqueue_id = -1;
static struct kevent eventQ[MAX_EVENT_QUEUE];
static int numEvents = 0;

static void kevent_add(struct kevent *e)
{
   if(kqueue_id == -1)
      abort();

   memcpy(&eventQ[numEvents], e, sizeof(struct kevent));
   numEvents++;

   if(numEvents == MAX_EVENT_QUEUE)
   {
      if(kevent(kqueue_id, eventQ, numEvents, NULL, 0, NULL) < 0)
         sendto_realops_lev(DEBUG_LEV, "kevent() returned error: %s", strerror(errno));
      numEvents = 0;
   }
}

void engine_init()
{
   kqueue_id = kqueue();
   numEvents = 0;
}

void engine_add_fd(int fd)
{
   struct kevent e;

   e.ident = fd;
   e.filter = EVFILT_READ;
   e.flags = EV_ADD|EV_DISABLE;
   e.fflags = 0;
   e.data = 0;
   e.udata = NULL;
   kevent_add(&e);

   e.ident = fd;
   e.filter = EVFILT_WRITE;
   e.flags = EV_ADD|EV_DISABLE;
   e.fflags = 0;
   e.data = 0;
   e.udata = NULL;
   kevent_add(&e);

   set_fd_internal(fd, 0);
}

void engine_del_fd(int fd)
{
   struct kevent e;

   e.ident = fd;
   e.filter = EVFILT_READ;
   e.flags = EV_DELETE;
   e.fflags = 0;
   e.data = 0;
   e.udata = NULL;
   kevent_add(&e);

   e.ident = fd;
   e.filter = EVFILT_WRITE;
   e.flags = EV_DELETE;
   e.fflags = 0;
   e.data = 0;
   e.udata = NULL;
   kevent_add(&e);
}

void engine_change_fd_state(int fd, unsigned int stateplus)
{
   unsigned int oldflags = (unsigned int) get_fd_internal(fd);
   struct kevent e;

   /* Something changed with our read state? */
   if((oldflags ^ stateplus) & FDF_WANTREAD)
   {
      e.ident = fd;
      e.filter = EVFILT_READ;
      e.flags = EV_ADD | ((stateplus & FDF_WANTREAD) ? EV_ENABLE : EV_DISABLE);
      e.fflags = 0;
      e.data = 0;
      e.udata = 0;
      kevent_add(&e);
   }

   /* Something changed with our write state? */
   if((oldflags ^ stateplus) & FDF_WANTWRITE)
   {
      e.ident = fd;
      e.filter = EVFILT_WRITE;
      e.flags = EV_ADD | ((stateplus & FDF_WANTWRITE) ? EV_ENABLE : EV_DISABLE);
      e.fflags = 0;
      e.data = 0;
      e.udata = 0;
      kevent_add(&e);
   }

   set_fd_internal(fd, (void *) stateplus);
}

#define ENGINE_MAX_EVENTS 512
#define ENGINE_MAX_LOOPS (2 * (MAXCONNECTIONS / 512))

int engine_read_message(time_t delay)
{
   static char errmsg[512];
   static struct kevent events[ENGINE_MAX_EVENTS];

   int nevs, length, i, numloops, eventsfull;
   unsigned int fdflags;
   int fdtype;
   void *fdvalue;
   aClient *cptr;
   struct timespec wait;

   numloops = 0;
   wait.tv_sec = delay;
   wait.tv_nsec = 0;

   do
   {
      nevs = kevent(kqueue_id, eventQ, numEvents, events, ENGINE_MAX_EVENTS, &wait);
      numEvents = 0;

      if (nevs == -1)
      {
         if((errno == EINTR) || (errno == EAGAIN))
            return -1;

         report_error("kevent %s:%s", &me);
         sleep(5);
         return -1;
      }

      eventsfull = (nevs == ENGINE_MAX_EVENTS) ? 1 : 0;
      if(delay || numloops)
         NOW = timeofday = time(NULL);
      numloops++;
      
      for(i = 0; i < nevs; i++)
      {
         int rr = 0, rw = 0;

         get_fd_info(events[i].ident, &fdtype, &fdflags, &fdvalue);

         if(events[i].filter == EVFILT_READ)
            rr = 1;
         else if(events[i].filter == EVFILT_WRITE)
            rw = 1;

         cptr = NULL;
         length = -1;

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
               continue;

            default:
               abort(); /* unknown client type? bail! */
         }
      }
   } while(eventsfull && (numloops < ENGINE_MAX_LOOPS));

   return 0;
}
