/************************************************************************
 *   IRC - Internet Relay Chat, src/drone.c
 *   Copyright (C) 2002, DALnet coding team
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

/*
 *
 * NOTE
 * 
 * This file is essentially for drone detection functions,
 * to be called from register_user.
 *
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "channel.h"
#include "throttle.h"
#include "h.h"

#ifndef USE_DRONEMODULE
/* Simply ignore all this stuff. */
void drone_init() { }
void drone_rehash() { }
int is_a_drone(aClient *sptr) { return 0; }
char *drone_mod_version(char *a, int b) { return NULL; }
#else

#include <dlfcn.h>
#define DRONEMODULENAME "drone.so"

void *drone_module_handle = NULL;
void (*get_drone_module_version)(char **v) = NULL;
int (*drone_module_func)(char *n, char *u, char *h, char *g, char **dstyle) = NULL;
int drones_ok = 0;

/*
 * drone_init
 * called once at ircd startup
 */
void drone_init()
{
   char *err;

   drone_module_handle = dlopen(DPATH DRONEMODULENAME, RTLD_NOW);
   if(drone_module_handle == NULL)
   {
      fprintf(stderr, "Error loading " DRONEMODULENAME ": %s\n", dlerror());
      return;
   }
   
   drone_module_func = dlsym(drone_module_handle, "check_drone");
   if((err = dlerror()) != NULL)
   {
      fprintf(stderr, "Error loading functions in " DRONEMODULENAME ": %s\n", err);
      dlclose(drone_module_handle);
      drone_module_handle = NULL;
      return;
   }

   get_drone_module_version = dlsym(drone_module_handle, "get_drone_module_version");
   if((err = dlerror()) != NULL)
   {
      fprintf(stderr, "Error loading functions in " DRONEMODULENAME ": %s\n", err);
      dlclose(drone_module_handle);
      drone_module_handle = NULL;
      return;
   }

   (*get_drone_module_version)(&err);
   fprintf(stderr, "Loaded " DRONEMODULENAME", version %s\n", err ? err : "unspecified");

   drones_ok = 1;
}

void drone_rehash()
{
   char *err;

   if(drones_ok)
   {
      dlclose(drone_module_handle);
      drone_module_handle = NULL;
      sendto_realops("Successfully unloaded " DRONEMODULENAME);
      drones_ok = 0;
   }

   drone_module_handle = dlopen(DPATH DRONEMODULENAME, RTLD_NOW);
   if(drone_module_handle == NULL)
   {
      sendto_realops("Error loading " DRONEMODULENAME ": %s\n", dlerror());
      return;
   }
   
   drone_module_func = dlsym(drone_module_handle, "check_drone");
   if((err = dlerror()) != NULL)
   {
      sendto_realops("Error loading functions in " DRONEMODULENAME ": %s\n", err);
      dlclose(drone_module_handle);
      drone_module_handle = NULL;
      return;
   }

   get_drone_module_version = dlsym(drone_module_handle, "get_drone_module_version");
   if((err = dlerror()) != NULL)
   {
      sendto_realops("Error loading functions in " DRONEMODULENAME ": %s\n", err);
      dlclose(drone_module_handle);
      drone_module_handle = NULL;
      return;
   }

   drones_ok = 1;

   (*get_drone_module_version)(&err);
   sendto_realops("Successfully loaded module " DRONEMODULENAME ". Version: %s", 
      err ? err : "unspecified");
}

/* 
 * is_a_drone:
 * main drone detection function.
 * returns 1 if client is a drone, zero otherwise.
 */
int is_a_drone(aClient *sptr)
{
   char *dstyle = NULL;

   if(drones_ok)
   {
      if((*drone_module_func)(sptr->name, sptr->user->username, sptr->user->host, sptr->info, &dstyle))
      {
         sendto_realops_lev(REJ_LEV, "Rejecting %s-style drone: %s (%s@%s) [%s]",
                            dstyle ? dstyle : "generic", 
                            sptr->name, sptr->user->username, sptr->user->host, sptr->info);

         return 1;
      }
   }
   return 0;
}

char *drone_mod_version(char *buf, int buflen)
{
   char *v = NULL;

   if(!drones_ok)
   {
      ircsnprintf(buf, buflen, "No drone module is currently installed.");
      return buf;
   }

   (*get_drone_module_version)(&v);
   ircsnprintf(buf, buflen, "%s", v ? v : "unspecified");
   return buf; 
}

#endif /* USE_DRONEMODULE */
