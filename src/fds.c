/************************************************************************
 *   IRC - Internet Relay Chat, src/fds.c
 *   Copyright (C) 2003 Lucas Madar
 *
 *   fds.c -- file descriptor list management routines
 *
 */

/* $Id$ */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "fds.h"
#include "numeric.h"

#include <sys/poll.h>

void engine_add_fd(int);
void engine_del_fd(int);
void engine_change_fd_state(int, unsigned int);

struct afd_entry {
   int type;
   void *value;
   unsigned int flags;
   void *internal;
};

struct afd_entry fd_list[MAXCONNECTIONS];

#define FDT_AUTH      1
#define FDT_RESOLVER  2
#define FDT_CLIENT    3
#define FDT_LISTENER  4

static char *type_string(int type)
{
   switch(type)
   {
      case FDT_NONE:
         return "NONE";

      case FDT_CLIENT:
         return "client";

      case FDT_AUTH:
         return "auth";

      case FDT_RESOLVER:
         return "resolver";

      case FDT_LISTENER:
         return "listener";
   }

   return "???";
}

static char *flags_string(unsigned int flags)
{
   static char fbuf[512];

   fbuf[0] = '\0';

   if(flags & FDF_WANTREAD)
   {
      if(fbuf[0])
         strcat(fbuf, ", ");
      strcat(fbuf, "read");
   }

   if(flags & FDF_WANTWRITE)
   {
      if(fbuf[0])
         strcat(fbuf, ", ");
      strcat(fbuf, "write");
   }

   return fbuf;
}

void report_fds(aClient *cptr)
{
   int i;
   char *name, *blocking;

   for(i = 0; i < MAXCONNECTIONS; i++)
   {
      if(fd_list[i].type == FDT_NONE)
         continue;

      if(fd_list[i].type == FDT_CLIENT ||
         fd_list[i].type == FDT_AUTH)
      {
         aClient *cptr = (aClient *) fd_list[i].value;
         int hide = (IsConnecting(cptr) || IsHandshake(cptr) || IsServer(cptr)) ? HIDEME : 0;

         name = get_client_name(cptr, hide);
         blocking = (cptr->flags & FLAGS_BLOCKED) ?
                    "BLOCKED" : "_";
      }
      else
      {
         name = "-";
         blocking = "-";
      }

      sendto_one(cptr, ":%s %d %s :%d - %s [%s] %s %s",
                 me.name, RPL_STATSDEBUG, cptr->name,
                 i, type_string(fd_list[i].type),
                 flags_string(fd_list[i].flags),
                 name, blocking);

   }
}

static inline void fd_range_assert(int fd)
{
   if(fd < 0 || fd >= MAXCONNECTIONS)
      abort();
}

static inline void fd_notused_assert(int fd)
{
   if(fd_list[fd].type != FDT_NONE)
      abort();
}

static inline void fd_used_assert(int fd)
{
   if(fd_list[fd].type == FDT_NONE)
      abort();
}

void add_fd(int fd, int type, void *value)
{
   fdfprintf(stderr, "add_fd: %d %d %x\n", fd, type, (int) value);

   fd_range_assert(fd);
   fd_notused_assert(fd);

   fd_list[fd].type = type;
   fd_list[fd].value = value;
   fd_list[fd].flags = 0;
   engine_add_fd(fd);
}

void del_fd(int fd)
{
   fdfprintf(stderr, "del_fd: %d\n", fd);

   fd_range_assert(fd);
   fd_used_assert(fd);

   engine_del_fd(fd);

   fd_list[fd].type = FDT_NONE;
   fd_list[fd].value = NULL;
   fd_list[fd].internal = NULL;
}

void set_fd_flags(int fd, unsigned int flags)
{
   int oldflags;
   fd_range_assert(fd);
   fd_used_assert(fd);

   oldflags = fd_list[fd].flags;

   fd_list[fd].flags |= flags;

   fdfprintf(stderr, "set_fd_flags: %d %x [%x -> %x]\n", fd, flags, oldflags, fd_list[fd].flags);

   if(oldflags != fd_list[fd].flags)
      engine_change_fd_state(fd, fd_list[fd].flags);
}

void unset_fd_flags(int fd, unsigned int flags)
{
   int oldflags;
   fd_range_assert(fd);
   fd_used_assert(fd);

   oldflags = fd_list[fd].flags;

   fd_list[fd].flags &= ~(flags);

   fdfprintf(stderr, "unset_fd_flags: %d %x [%x -> %x]\n", fd, flags, oldflags, fd_list[fd].flags);
   if(oldflags != fd_list[fd].flags)
      engine_change_fd_state(fd, fd_list[fd].flags);
}

void get_fd_info(int fd, int *type, unsigned int *flags, void **value)
{
   fd_range_assert(fd);

   *type = fd_list[fd].type;
   *flags = fd_list[fd].flags;
   *value = fd_list[fd].value;
}

unsigned int get_fd_flags(int fd)
{
   fd_range_assert(fd);
   fd_used_assert(fd);

   return fd_list[fd].flags;
}

void init_fds()
{
   memset(fd_list, 0, sizeof(struct afd_entry) * MAXCONNECTIONS);
}

void set_fd_internal(int fd, void *ptr)
{
   fd_list[fd].internal = ptr;
}

void *get_fd_internal(int fd)
{
   return fd_list[fd].internal;
}

/////////////////////////////////////////////////////////

/*
 * check_client_fd
 * 
 * called whenever a state change is necessary on a client
 * ie, when ident and dns are finished
 */

void check_client_fd(aClient *cptr)
{
   if (DoingAuth(cptr))
   {
      unsigned int fdflags = get_fd_flags(cptr->authfd);

      if(!(fdflags & FDF_WANTREAD))
         set_fd_flags(cptr->authfd, FDF_WANTREAD);

      if((cptr->flags & FLAGS_WRAUTH) && !(fdflags & FDF_WANTWRITE))
         set_fd_flags(cptr->authfd, FDF_WANTWRITE);
      else if(!(cptr->flags & FLAGS_WRAUTH) && (fdflags & FDF_WANTWRITE))
         unset_fd_flags(cptr->authfd, FDF_WANTWRITE);

      return;
   }

   if (DoingDNS(cptr))
      return;

   set_fd_flags(cptr->fd, FDF_WANTREAD);
}
