/************************************************************************
 *   IRC - Internet Relay Chat, src/modules.c
 *   Copyright (C) 2003, Lucas Madar
 */

#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "msg.h"
#include "channel.h"
#include "throttle.h"
#include "h.h"
#include "hooks.h"

#ifndef USE_HOOKMODULES
int m_module(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
   return 0;
}

int call_hooks(enum c_hooktype hooktype, ...)
{
   return 0;
}
#else

#include <dlfcn.h>

DLink *module_list = NULL;

typedef struct loaded_module {
   char *name;

   char *version;
   char *description;

   void *handle;

   void (*module_check) (int *);
   int (*module_init) (void *);
   void (*module_shutdown) (void);
   void (*module_getinfo) (char **, char **);
   int (*module_command) (aClient *, int, char **);
} aModule;

/* Forward decls */
char *bircmodule_strdup(char *);
void *bircmodule_malloc(int);
void bircmodule_free(void *);
void drop_all_hooks(aModule *owner);
void list_hooks(aClient *sptr);

aModule *find_module(char *name) 
{
   DLink *lp;

   for(lp = module_list; lp; lp = lp->next)
   {
      aModule *mod = (aModule *) lp->value.cp;

      if(strcmp(mod->name, name) == 0)
         return mod;
   }

   return NULL;
}

aModule *find_module_opaque(void *opaque) 
{
   DLink *lp;

   for(lp = module_list; lp; lp = lp->next)
   {
      aModule *mod = (aModule *) lp->value.cp;

      if(opaque == (void *) mod)
         return mod;
   }

   return NULL;
}

int modsym_load(aClient *sptr, char *modname, char *symbol, void *modulehandle, void **retfunc)
{
   void *ret;
   char *error;

   ret = dlsym(modulehandle, symbol);

   if((error = dlerror()) != NULL)
   {
      sendto_one(sptr, ":%s NOTICE %s :Module symbol error for %s/%s: %s",
                 me.name, sptr->name, modname, symbol, error);
      dlclose(modulehandle);
      return 0;
   }

   *retfunc = ret;
   return 1;
}

void list_modules(aClient *sptr)
{
   DLink *lp;

   for(lp = module_list; lp; lp = lp->next)
   {
      aModule *mod = (aModule *) lp->value.cp;
      sendto_one(sptr, ":%s NOTICE %s :Module: %s    Version: %s",
                 me.name, sptr->name, mod->name, mod->version);

      sendto_one(sptr, ":%s NOTICE %s :  - %s",
                 me.name, sptr->name, mod->description);
   }
}

void destroy_module(aModule *themod)
{
   (*themod->module_shutdown)();
   dlclose(themod->handle);
   bircmodule_free(themod->name);
   bircmodule_free(themod->version);
   bircmodule_free(themod->description);   
   remove_from_list(&module_list, themod, NULL);
   bircmodule_free(themod);
}

int load_module(aClient *sptr, char *modname)
{
   aModule tmpmod, *themod;
   char mnamebuf[512], *ver, *desc;
   int acsz = -1, ret;

   if((themod = find_module(modname)))
   {
      sendto_one(sptr, ":%s NOTICE %s :Module %s is already loaded [version: %s]",
                 me.name, sptr->name, modname, themod->version);
      return 0;
   }

   ircsnprintf(mnamebuf, 512, DPATH "modules/%s.so", modname);

   tmpmod.handle = dlopen(mnamebuf, RTLD_NOW);
   if(tmpmod.handle == NULL)
   {
      sendto_one(sptr, ":%s NOTICE %s :Module load error for %s: %s",
                 me.name, sptr->name, modname, dlerror());
      return -1;
   }

   if(!modsym_load(sptr, modname, "bircmodule_check", tmpmod.handle, (void **) &tmpmod.module_check))
      return -1;
   if(!modsym_load(sptr, modname, "bircmodule_init", tmpmod.handle, (void **) &tmpmod.module_init))
      return -1;
   if(!modsym_load(sptr, modname, "bircmodule_shutdown", tmpmod.handle, (void **) &tmpmod.module_shutdown))
      return -1;
   if(!modsym_load(sptr, modname, "bircmodule_getinfo", tmpmod.handle, (void **) &tmpmod.module_getinfo))
      return -1;
   if(!modsym_load(sptr, modname, "bircmodule_command", tmpmod.handle, (void **) &tmpmod.module_command))
      return -1;

   (*tmpmod.module_check)(&acsz);
   if(acsz != ACLIENT_SERIAL)
   {
      sendto_one(sptr, ":%s NOTICE %s :Module load error for %s: Incompatible module ("
                 "My serial: %d Module serial: %d)",
                 me.name, sptr->name, modname, ACLIENT_SERIAL, acsz);
      dlclose(tmpmod.handle);
      return -1;
   }

   tmpmod.name = bircmodule_strdup(modname);

   ver = desc = NULL;
   (*tmpmod.module_getinfo)(&ver, &desc);
   tmpmod.version = bircmodule_strdup((ver != NULL) ? ver : "<no version>");
   tmpmod.description = bircmodule_strdup((desc != NULL) ? desc : "<no description>");

   themod = (aModule *) bircmodule_malloc(sizeof(aModule));
   memcpy(themod, &tmpmod, sizeof(aModule));
   add_to_list(&module_list, themod);

   ret = (*themod->module_init)((void *) themod);

   if(ret == 0)
   {
      sendto_one(sptr, ":%s NOTICE %s :Module %s successfully loaded [version: %s]",
                 me.name, sptr->name, modname, themod->version);
   }
   else
   {
      drop_all_hooks(themod);
      destroy_module(themod);

      sendto_one(sptr, ":%s NOTICE %s :Module %s load failed (module requested unload)",
                 me.name, sptr->name, modname);
   }

   return 0;
}

int unload_module(aClient *sptr, char *modname)
{
   aModule *themod = find_module(modname);

   if(!themod)
   {
      sendto_one(sptr, ":%s NOTICE %s :Module %s is not loaded",
                 me.name, sptr->name, modname);
      return 0;
   }

   drop_all_hooks(themod);
   destroy_module(themod);

   sendto_one(sptr, ":%s NOTICE %s :Module %s successfully unloaded",
              me.name, sptr->name, modname);

   return 0;
}

int m_module(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
   if(!MyClient(sptr))
      return 0;

   if(!(IsAnOper(sptr) && IsAdmin(sptr)))
   {
      sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
      return 0;
   }
   else if(parc > 2 && mycmp(parv[1], "LOAD") == 0)
   {
      if(!BadPtr(parv[2]))
         load_module(sptr, parv[2]);
   }
   else if(parc > 2 && mycmp(parv[1], "UNLOAD") == 0)
   {
      if(!BadPtr(parv[2]))
         unload_module(sptr, parv[2]);
   }
   else if(parc > 1 && mycmp(parv[1], "LIST") == 0)
   {
      list_modules(sptr);
      sendto_one(sptr, ":%s NOTICE %s :--- End of module list ---",
                 me.name, sptr->name);
   }
   else if(parc > 1 && mycmp(parv[1], "HOOKS") == 0)
   {
      list_hooks(sptr);
      sendto_one(sptr, ":%s NOTICE %s :--- End of hook list ---",
                 me.name, sptr->name);
   }
   else if(parc > 2 && mycmp(parv[1], "CMD") == 0)
   {
      aModule *themod = find_module(parv[2]);
      if(!themod)
      {
         sendto_one(sptr, ":%s NOTICE %s :Module %s not found for cmd",
                    me.name, sptr->name, parv[2]);
         return 0;
      }
      return (*themod->module_command) (sptr, parc - 2, parv + 2);
   }

   return 0;
}


/////// module memory functions

char *bircmodule_strdup(char *string)
{
   char *ret = MyMalloc(strlen(string) + 1);
   strcpy(ret, string);
   return ret;
}

void *bircmodule_malloc(int size)
{
   return MyMalloc(size);
}

void bircmodule_free(void *p)
{
   MyFree(p);
}

//////// hook functions

typedef struct module_hook {
   aModule *owner;
   void *funcptr;
   int hooktype;
} aHook;

static DLink *preaccess_hooks = NULL;
static DLink *postaccess_hooks = NULL;
static DLink *msg_hooks = NULL;
static DLink *mymsg_hooks = NULL;
static DLink *every10_hooks = NULL;
static DLink *signoff_hooks = NULL;

static DLink *all_hooks = NULL;

char *get_texthooktype(enum c_hooktype hooktype)
{
   static char ubuf[32];

   switch(hooktype)
   {
      case CHOOK_10SEC:
         return "10 seconds";

      case CHOOK_PREACCESS:
         return "Pre-access";

      case CHOOK_POSTACCESS:
         return "Post-access";

      case CHOOK_MSG:
         return "Message";

      case CHOOK_MYMSG:
         return "Message to me";

      case CHOOK_SIGNOFF:
         return "Signoff";

      default:
         ircsnprintf(ubuf, 32, "Unknown (%d)", hooktype);
         return ubuf;
   }
}

DLink **get_hooklist(enum c_hooktype hooktype)
{
   DLink **hooklist;

   switch(hooktype)
   {
      case CHOOK_10SEC:
         hooklist = &every10_hooks;
         break;

      case CHOOK_PREACCESS:
         hooklist = &preaccess_hooks;
         break;

      case CHOOK_POSTACCESS:
         hooklist = &postaccess_hooks;
         break;

      case CHOOK_MSG:
         hooklist = &msg_hooks;
         break;

      case CHOOK_MYMSG:
         hooklist = &mymsg_hooks;
         break;

      case CHOOK_SIGNOFF:
         hooklist = &signoff_hooks;
         break;

      default:
         return NULL;
   }

   return hooklist;
}

void drop_all_hooks(aModule *owner)
{
   DLink *lp, *lpn, **hooklist;

   for(lp = all_hooks; lp; lp = lpn)
   {
      aHook *hk = (aHook *) lp->value.cp;

      lpn = lp->next;

      if(hk->owner == owner)
      {
         sendto_realops_lev(DEBUG_LEV, "Module cleanup: removing hook [%s] for opaque %d", 
                            get_texthooktype(hk->hooktype), (int) owner);

         hooklist = get_hooklist((enum c_hooktype) hk->hooktype);

         remove_from_list(hooklist, hk, NULL);
         remove_from_list(&all_hooks, hk, NULL);
         bircmodule_free(hk);
      }
   }
}

void *bircmodule_add_hook(enum c_hooktype hooktype, void *opaque, void *funcptr)
{
   DLink **hooklist;
   aHook *hk;
   aModule *owner;

   if(!(owner = find_module_opaque(opaque)))
   {
      sendto_realops_lev(DEBUG_LEV, "Module tried to add hooktype %d with unknown opaque 0x%x",
                         (int) hooktype, (int) opaque);
      return NULL;
   }

   if((hooklist = get_hooklist(hooktype)) == NULL)
      return NULL;

   hk = (aHook *) bircmodule_malloc(sizeof(aHook));
   hk->owner = owner;
   hk->funcptr = funcptr;
   hk->hooktype = (int) hooktype;

   add_to_list(&all_hooks, hk);
   add_to_list(hooklist, hk);

   return (void *) hk;
}

void bircmodule_del_hook(void *opaque)
{
   DLink *lp, *lpn, **hooklist;

   for(lp = all_hooks; lp; lp = lpn)
   {
      aHook *hk = (aHook *) lp->value.cp;

      lpn = lp->next;

      if((void *) hk == opaque)
      {
         hooklist = get_hooklist((enum c_hooktype) hk->hooktype);

         remove_from_list(hooklist, hk, NULL);
         remove_from_list(&all_hooks, hk, NULL);
         bircmodule_free(hk);
      }
   }
}

int call_hooks(enum c_hooktype hooktype, ...)
{
   va_list vl;
   int ret = 0;
   aClient *acptr;
   char *txtptr;
   int aint;
   DLink *lp;

   va_start(vl, hooktype);

   switch(hooktype)
   {
      case CHOOK_10SEC:
         for(lp = every10_hooks; lp; lp = lp->next)
         {
            void (*rfunc) () = ((aHook *)lp->value.cp)->funcptr;
            (*rfunc)();
         }
         break;

      case CHOOK_PREACCESS:
         acptr = va_arg(vl, aClient *);
         for(lp = preaccess_hooks; lp; lp = lp->next)
         {
            int (*rfunc) (aClient *) = ((aHook *)lp->value.cp)->funcptr;
            if((ret = (*rfunc)(acptr)) == FLUSH_BUFFER)
               break;
         }
         break;

      case CHOOK_POSTACCESS:
         acptr = va_arg(vl, aClient *);
         for(lp = postaccess_hooks; lp; lp = lp->next)
         {
            int (*rfunc) (aClient *) = ((aHook *)lp->value.cp)->funcptr;
            if((ret = (*rfunc)(acptr)) == FLUSH_BUFFER)
               break;
         }
         break;

      case CHOOK_MSG:
         acptr = va_arg(vl, aClient *);
         aint = va_arg(vl, int);
         txtptr = va_arg(vl, char *);
         for(lp = msg_hooks; lp; lp = lp->next)
         {
            int (*rfunc) (aClient *, int, char *) = ((aHook *)lp->value.cp)->funcptr;
            if((ret = (*rfunc)(acptr, aint, txtptr)) == FLUSH_BUFFER)
               break;
         }
         break;

      case CHOOK_MYMSG:
         acptr = va_arg(vl, aClient *);
         aint = va_arg(vl, int);
         txtptr = va_arg(vl, char *);
         for(lp = mymsg_hooks; lp; lp = lp->next)
         {
            int (*rfunc) (aClient *, int, char *) = ((aHook *)lp->value.cp)->funcptr;
            if((ret = (*rfunc)(acptr, aint, txtptr)) == FLUSH_BUFFER)
               break;
         }
         break;

      case CHOOK_SIGNOFF:
         acptr = va_arg(vl, aClient *);
         for(lp = signoff_hooks; lp; lp = lp->next)
         {
            void (*rfunc) (aClient *) = ((aHook *)lp->value.cp)->funcptr;
            (*rfunc)(acptr);
         }
         break;
      
      default:
         sendto_realops_lev(DEBUG_LEV, "Call for unknown hook type %d", hooktype);
         break;
   }   

   va_end(vl);
   return ret;
}

void list_hooks(aClient *sptr)
{
   DLink *lp;

   for(lp = all_hooks; lp; lp = lp->next)
   {
      aHook *hook = (aHook *) lp->value.cp;
      aModule *mod = hook->owner;

      sendto_one(sptr, ":%s NOTICE %s :Module: %s  Type: %s",
                 me.name, sptr->name, mod->name, get_texthooktype(hook->hooktype));
   }
}
#endif
