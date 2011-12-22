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
#include "memcount.h"

extern Conf_Modules *modules;

#ifndef USE_HOOKMODULES
int 
m_module(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    if(MyClient(sptr) && !IsAnOper(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    if (parc > 2)
    {
        if (!mycmp(parv[1], "LIST") || !mycmp(parv[1], "HOOKS"))
        {
            if (hunt_server(cptr, sptr, "%s MODULE %s %s", 2, parc, parv)
                != HUNTED_ISME)
                return 0;
        }
        else if (!mycmp(parv[1], "CGLOBAL"))
        {
            char pbuf[512];

            if(!(IsServer(sptr) || IsULine(sptr)))
                return 0;

            /* Pass this on to all servers! */
            make_parv_copy(pbuf, parc, parv);
            sendto_serv_butone(cptr, ":%s MODULE %s", parv[0], pbuf);

            return 0;
        }
    }

    if (IsPerson(sptr))
        sendto_one(sptr, "%s NOTICE %s :I don't have module support.",
                   me.name, sptr->name);

    return 0;
}

int 
call_hooks(enum c_hooktype hooktype, ...)
{
    return 0;
}

int 
init_modules()
{
    return 0;
}

#else

#include <dlfcn.h>

/* XXX hack.  check on RTLD_NOW later. */
#ifndef RTLD_NOW
#define RTLD_NOW 0
#endif

DLink *module_list = NULL;

typedef struct loaded_module 
{
    char *name;

    char *version;
    char *description;

    void *handle;

    void (*module_check) (int *);
    int  (*module_init) (void *);
    void (*module_shutdown) (void);
    void (*module_getinfo) (char **, char **);
    int  (*module_command) (aClient *, int, char **);
    int  (*module_globalcommand) (aClient *, aClient *, int, char **);
} aModule;

/* Forward decls */
char *bircmodule_strdup(char *);
void *bircmodule_malloc(int);
void  bircmodule_free(void *);
void  drop_all_hooks(aModule *owner);
void  list_hooks(aClient *sptr);

aModule *
find_module(char *name) 
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

aModule *
find_module_opaque(void *opaque) 
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

int 
modsym_load(aClient *sptr, char *modname, char *symbol, void *modulehandle, 
            void **retfunc)
{
    void *ret;
    const char *error;

    /* Clear dlerror() to make sure we're dealing with our own error. */
    dlerror();

    ret = dlsym(modulehandle, symbol);
    error = dlerror();

    /* Even if there was no error, ret must not be NULL or we will crash. */
    if(error == NULL && ret == NULL)
	error = "dlsym returned NULL";

    if(error != NULL)
    {
        if(sptr)
            sendto_one(sptr, ":%s NOTICE %s :Module symbol error for %s/%s: %s",
                       me.name, sptr->name, modname, symbol, error);
        else
            fprintf(stderr, " - Module symbol error for %s/%s: %s\n",
                    modname, symbol, error);
        
        dlclose(modulehandle);
        return 0;
    }

    *retfunc = ret;
    return 1;
}

void 
list_modules(aClient *sptr)
{
    DLink *lp;

    for(lp = module_list; lp; lp = lp->next)
    {
        aModule *mod = (aModule *) lp->value.cp;
        sendto_one(sptr, ":%s NOTICE %s :Module: %s    Version: %s",
                   me.name, sptr->name, mod->name, mod->version);

        sendto_one(sptr, ":%s NOTICE %s :  - %s", me.name, sptr->name, 
                   mod->description);
    }
}

void 
destroy_module(aModule *themod)
{
    (*themod->module_shutdown)();
    dlclose(themod->handle);
    bircmodule_free(themod->name);
    bircmodule_free(themod->version);
    bircmodule_free(themod->description);   
    remove_from_list(&module_list, themod, NULL);
    bircmodule_free(themod);
}

int 
load_module(aClient *sptr, char *modname)
{
    aModule tmpmod, *themod;
    char mnamebuf[512], *ver, *desc;
    int acsz = -1, ret;

    if((themod = find_module(modname)))
    {
        if(sptr)
            sendto_one(sptr, ":%s NOTICE %s :Module %s is already loaded"
                       " [version: %s]", me.name, sptr->name, modname, 
                       themod->version);
        else
            fprintf(stderr, " - Module %s is already loaded [version: %s]\n",
                    modname, themod->version);
        return 0;
    }

    if(modules && modules->module_path)
        ircsnprintf(mnamebuf, 512, "%s/%s.so", modules->module_path, modname);
    else
        ircsnprintf(mnamebuf, 512, "%s/modules/%s.so", dpath, modname);

    tmpmod.handle = dlopen(mnamebuf, RTLD_NOW);
    if(tmpmod.handle == NULL)
    {
        if(sptr)
            sendto_one(sptr, ":%s NOTICE %s :Module load error for %s: %s",
                       me.name, sptr->name, modname, dlerror());
        else
            fprintf(stderr, " - Module load error for %s: %s\n",
                    modname, dlerror());
        return -1;
    }

    if(!modsym_load(sptr, modname, "bircmodule_check", tmpmod.handle, 
                    (void *) &tmpmod.module_check))
        return -1;
    if(!modsym_load(sptr, modname, "bircmodule_init", tmpmod.handle, 
                    (void *) &tmpmod.module_init))
        return -1;
    if(!modsym_load(sptr, modname, "bircmodule_shutdown", tmpmod.handle, 
                    (void *) &tmpmod.module_shutdown))
        return -1;
    if(!modsym_load(sptr, modname, "bircmodule_getinfo", tmpmod.handle, 
                    (void *) &tmpmod.module_getinfo))
        return -1;
    if(!modsym_load(sptr, modname, "bircmodule_command", tmpmod.handle, 
                    (void *) &tmpmod.module_command))
        return -1;
    if(!modsym_load(sptr, modname, "bircmodule_globalcommand", tmpmod.handle, 
                    (void *) &tmpmod.module_globalcommand))
        return -1;

    (*tmpmod.module_check)(&acsz);
    if(acsz != MODULE_INTERFACE_VERSION)
    {
        if(sptr)
            sendto_one(sptr, ":%s NOTICE %s :Module load error for %s:"
                    " Incompatible module (My interface version: %d Module"
                    " version: %d)", me.name, sptr->name, modname, 
                    MODULE_INTERFACE_VERSION, acsz);
        else
            fprintf(stderr, " - Module load error for %s: Incompatible module ("
                            "My interface version: %d Module version: %d)\n",
                    modname, MODULE_INTERFACE_VERSION, acsz);
        dlclose(tmpmod.handle);
        return -1;
    }

    tmpmod.name = bircmodule_strdup(modname);

    ver = desc = NULL;
    (*tmpmod.module_getinfo)(&ver, &desc);
    tmpmod.version = bircmodule_strdup((ver != NULL) ? ver : "<no version>");
    tmpmod.description = bircmodule_strdup((desc != NULL) ? desc : 
                                                           "<no description>");
    themod = (aModule *) bircmodule_malloc(sizeof(aModule));
    memcpy(themod, &tmpmod, sizeof(aModule));
    add_to_list(&module_list, themod);

    ret = (*themod->module_init)((void *) themod);

    if(ret == 0)
    {
        if(sptr)
            sendto_one(sptr, ":%s NOTICE %s :Module %s successfully loaded"
                       " [version: %s]", me.name, sptr->name, modname, 
                       themod->version);
        else
            fprintf(stderr, " - Module %s successfully loaded [version: %s]\n",
                    modname, themod->version);

        call_hooks(MHOOK_LOAD, modname, (void *) themod);
    }
    else
    {
        drop_all_hooks(themod);
        destroy_module(themod);

        if(sptr)
            sendto_one(sptr, ":%s NOTICE %s :Module %s load failed (module"
                        " requested unload)", me.name, sptr->name, modname);
        else
            fprintf(stderr, " - Module %s load failed (module requested"
                            " unload)\n", modname);
    }
    return 0;
}

int 
unload_module(aClient *sptr, char *modname)
{
    aModule *themod = find_module(modname);

    if(!themod)
    {
        sendto_one(sptr, ":%s NOTICE %s :Module %s is not loaded",
                   me.name, sptr->name, modname);
        return 0;
    }

    drop_all_hooks(themod);
    call_hooks(MHOOK_UNLOAD, themod->name, (void *) themod);
    destroy_module(themod);

    sendto_one(sptr, ":%s NOTICE %s :Module %s successfully unloaded",
               me.name, sptr->name, modname);

    return 0;
}

int 
m_module(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    if(!IsAnOper(sptr))
    {
        sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
        return 0;
    }

    if(parc < 2)
    {
        sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name,
                        parv[0], "MODULE");
        return 0;
    }

    /* this should technically never happen anyway, but.. */
    if(!MyClient(sptr) && !(IsAnOper(sptr) || IsULine(sptr) || IsServer(sptr)))
        return 0;

    if(mycmp(parv[1], "LOAD") == 0)
    {
        if(!(MyClient(sptr) && IsAdmin(sptr)))
        {
            sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
            return 0;
        }
        if(!BadPtr(parv[2]))
            load_module(sptr, parv[2]);
        else
        {
            sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name,
                       parv[0], "MODULE");
            return 0;
        }

    }
    else if(mycmp(parv[1], "UNLOAD") == 0)
    {
        if(!(MyClient(sptr) && IsAdmin(sptr)))
        {
            sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
            return 0;
        }
        if(!BadPtr(parv[2]))
            unload_module(sptr, parv[2]);
        else
        {
            sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name,
                       parv[0], "MODULE");
            return 0;
        }
    }
    else if(mycmp(parv[1], "LIST") == 0)
    {
        if(parc > 2 && hunt_server(cptr, sptr, ":%s MODULE %s %s", 2,
                       parc, parv) != HUNTED_ISME)
            return 0;

        list_modules(sptr);
        sendto_one(sptr, ":%s NOTICE %s :--- End of module list ---",
                   me.name, sptr->name);
    }
    else if(mycmp(parv[1], "HOOKS") == 0)
    {
        if(parc > 2 && hunt_server(cptr, sptr, ":%s MODULE %s %s", 2,
                                   parc, parv) != HUNTED_ISME)
            return 0;

        list_hooks(sptr);
        sendto_one(sptr, ":%s NOTICE %s :--- End of hook list ---",
                   me.name, sptr->name);
    }
    else if(mycmp(parv[1], "CMD") == 0)
    {
        aModule *themod;
        if(!(MyClient(sptr) && IsAdmin(sptr)))
        {
            sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
            return 0;
        }
        if(BadPtr(parv[2]))
        {
            sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name,
                       parv[0], "MODULE");
            return 0;
        }
        themod = find_module(parv[2]);
        if(!themod)
        {
            sendto_one(sptr, ":%s NOTICE %s :Module %s not found for cmd",
                       me.name, sptr->name, parv[2]);
            return 0;
        }
        return (*themod->module_command) (sptr, parc - 2, parv + 2);
    }
    else if(parc > 2 && mycmp(parv[1], "CGLOBAL") == 0)
    {
        char pbuf[512];
        aModule *themod;

        if(!(IsServer(sptr) || IsULine(sptr)))
            return 0;

        themod = find_module(parv[2]);

        /* Pass this on to all servers! */
        make_parv_copy(pbuf, parc, parv);
        sendto_serv_butone(cptr, ":%s MODULE %s", parv[0], pbuf);

        if(themod)
            return (*themod->module_globalcommand) 
                                            (cptr, sptr, parc - 2, parv + 2);
    }
    return 0;
}


/* module memory functions */

char *
bircmodule_strdup(char *string)
{
    char *ret = MyMalloc(strlen(string) + 1);
    strcpy(ret, string);
    return ret;
}

void *
bircmodule_malloc(int size)
{
    return MyMalloc(size);
}

void 
bircmodule_free(void *p)
{
    MyFree(p);
}

/* hook functions */

typedef struct module_hook 
{
    aModule *owner;
    void *funcptr;
    int hooktype;
} aHook;

static DLink *preaccess_hooks = NULL;
static DLink *postaccess_hooks = NULL;
static DLink *postmotd_hooks = NULL;
static DLink *msg_hooks = NULL;
static DLink *chanmsg_hooks = NULL;
static DLink *usermsg_hooks = NULL;
static DLink *mymsg_hooks = NULL;
static DLink *every10_hooks = NULL;
static DLink *join_hooks = NULL;
static DLink *sendburst_hooks = NULL;
static DLink *throttle_hooks = NULL;
static DLink *forbid_hooks = NULL;
static DLink *signoff_hooks = NULL;
static DLink *mload_hooks = NULL;
static DLink *munload_hooks = NULL;

static DLink *all_hooks = NULL;

char *
get_texthooktype(enum c_hooktype hooktype)
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

        case CHOOK_POSTMOTD:
            return "Post-MOTD";

        case CHOOK_MSG:
            return "Message";

        case CHOOK_CHANMSG:
            return "Channel Message";

        case CHOOK_USERMSG:
            return "User targeted Message";

        case CHOOK_MYMSG:
            return "Message to me";

        case CHOOK_JOIN:
            return "Join";

        case CHOOK_SENDBURST:
            return "netburst";

        case CHOOK_THROTTLE:
            return "throttle";

        case CHOOK_FORBID:
            return "forbid";

        case CHOOK_SIGNOFF:
            return "Signoff";

        case MHOOK_LOAD:
            return "Module load";

        case MHOOK_UNLOAD:
            return "Module unload";

        default:
            ircsnprintf(ubuf, 32, "Unknown (%d)", hooktype);
            return ubuf;
    }
}

DLink **
get_hooklist(enum c_hooktype hooktype)
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

        case CHOOK_POSTMOTD:
            hooklist = &postmotd_hooks;
            break;

        case CHOOK_MSG:
            hooklist = &msg_hooks;
            break;

        case CHOOK_CHANMSG:
            hooklist = &chanmsg_hooks;
            break;

        case CHOOK_USERMSG:
            hooklist = &usermsg_hooks;
            break;

        case CHOOK_MYMSG:
            hooklist = &mymsg_hooks;
            break;

        case CHOOK_JOIN:
            hooklist = &join_hooks;
            break;

        case CHOOK_SENDBURST:
            hooklist = &sendburst_hooks;
            break;

        case CHOOK_THROTTLE:
            hooklist = &throttle_hooks;
            break;

        case CHOOK_FORBID:
            hooklist = &forbid_hooks;
            break;

        case CHOOK_SIGNOFF:
            hooklist = &signoff_hooks;
            break;

        case MHOOK_LOAD:
            hooklist = &mload_hooks;
            break;

        case MHOOK_UNLOAD:
            hooklist = &munload_hooks;
            break;

        default:
            return NULL;
    }
    return hooklist;
}

void 
drop_all_hooks(aModule *owner)
{
    DLink *lp, *lpn, **hooklist;

    for(lp = all_hooks; lp; lp = lpn)
    {
        aHook *hk = (aHook *) lp->value.cp;

        lpn = lp->next;

        if(hk->owner == owner)
        {
            sendto_realops_lev(DEBUG_LEV, "Module cleanup: removing hook [%s]"
                            " for opaque %lu", get_texthooktype(hk->hooktype), 
                            (u_long) owner);

            hooklist = get_hooklist((enum c_hooktype) hk->hooktype);

            remove_from_list(hooklist, hk, NULL);
            remove_from_list(&all_hooks, hk, NULL);
            bircmodule_free(hk);
        }
    }
}

void *
bircmodule_add_hook(enum c_hooktype hooktype, void *opaque, void *funcptr)
{
    DLink **hooklist;
    aHook *hk;
    aModule *owner;

    if(!(owner = find_module_opaque(opaque)))
    {
        sendto_realops_lev(DEBUG_LEV, "Module tried to add hooktype %lu with"
                         " unknown opaque %p", (u_long) hooktype, opaque);
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

void 
bircmodule_del_hook(void *opaque)
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

int 
call_hooks(enum c_hooktype hooktype, ...)
{
    va_list vl;
    int ret = 0;
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
            {
                aClient *acptr = va_arg(vl, aClient *);

                for(lp = preaccess_hooks; lp; lp = lp->next)
                {
                    int (*rfunc) (aClient *) = ((aHook *)lp->value.cp)->funcptr;
                    if((ret = (*rfunc)(acptr)) == FLUSH_BUFFER)
                        break;
                }
                break;
            }

        case CHOOK_POSTACCESS:
            {
                aClient *acptr = va_arg(vl, aClient *);

                for(lp = postaccess_hooks; lp; lp = lp->next)
                {
                    int (*rfunc) (aClient *) = ((aHook *)lp->value.cp)->funcptr;
                    if((ret = (*rfunc)(acptr)) == FLUSH_BUFFER)
                        break;
                }
                break;
            }

        case CHOOK_POSTMOTD:
            {
                aClient *acptr = va_arg(vl, aClient *);

                for(lp = postmotd_hooks; lp; lp = lp->next)
                {
                    int (*rfunc) (aClient *) = ((aHook *)lp->value.cp)->funcptr;
                    if((ret = (*rfunc)(acptr)) == FLUSH_BUFFER)
                        break;
                }
                break;
            }

        case CHOOK_MSG:
            {
                aClient *acptr = va_arg(vl, aClient *);
                int aint = va_arg(vl, int);
                char *txtptr = va_arg(vl, char *);

                for(lp = msg_hooks; lp; lp = lp->next)
                {
                    int (*rfunc) (aClient *, int, char *) = 
                                    ((aHook *)lp->value.cp)->funcptr;
                    if((ret = (*rfunc)(acptr, aint, txtptr)) == FLUSH_BUFFER)
                        break;
                }
                break;
            }

        case CHOOK_CHANMSG:
            {
                aClient *acptr = va_arg(vl, aClient *);
                aChannel *chptr = va_arg(vl, aChannel *);
                int aint = va_arg(vl, int);
                char *txtptr = va_arg(vl, char *);

                for(lp = chanmsg_hooks; lp; lp = lp->next)
                {
                    int (*rfunc) (aClient *, aChannel *, int, char *) =
                                  ((aHook *)lp->value.cp)->funcptr;
                    if((ret = (*rfunc)(acptr, chptr, aint, txtptr)) 
                                    == FLUSH_BUFFER)
                        break;
                }
                break;
            }

        case CHOOK_USERMSG:
            {
                aClient *acptr = va_arg(vl, aClient *);
                aClient *dcptr = va_arg(vl, aClient *);
                int aint = va_arg(vl, int);
                char *txtptr = va_arg(vl, char *);

                for(lp = usermsg_hooks; lp; lp = lp->next)
                {
                    int (*rfunc) (aClient *, aClient *, int, char *) =
                                 ((aHook *)lp->value.cp)->funcptr;
                    if((ret = (*rfunc)(acptr, dcptr, aint, txtptr))
                                    == FLUSH_BUFFER)
                        break;
                }
                break;
            }

        case CHOOK_MYMSG:
            {
                aClient *acptr = va_arg(vl, aClient *);
                int aint = va_arg(vl, int);
                char *txtptr = va_arg(vl, char *);
    
                for(lp = mymsg_hooks; lp; lp = lp->next)
                {  
                    int (*rfunc) (aClient *, int, char *) = 
                                 ((aHook *)lp->value.cp)->funcptr;
                    if((ret = (*rfunc)(acptr, aint, txtptr)) == FLUSH_BUFFER)
                        break;
                }
                break;
            }

        case CHOOK_JOIN:
            {
                aClient *acptr = va_arg(vl, aClient *);
                aChannel *chptr = va_arg(vl, aChannel *);

                for(lp = join_hooks; lp; lp = lp->next)
                {
                    int (*rfunc) (aClient *, aChannel *) = 
                                    ((aHook *)lp->value.cp)->funcptr;
                    if((ret = (*rfunc)(acptr, chptr)) == FLUSH_BUFFER)
                        break;
                }
                break;
            }

        case CHOOK_SENDBURST:
            {
                aClient *acptr = va_arg(vl, aClient *);
                for(lp = sendburst_hooks; lp; lp = lp->next)
                {
                    void (*rfunc) (aClient *) = 
                                    ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(acptr);
                }
                break;
            }

        case CHOOK_THROTTLE:
            {
                aClient *acptr = va_arg(vl, aClient *);
                aChannel *chptr = va_arg(vl, aChannel *);
                int type = va_arg(vl, int);
                int jnum = va_arg(vl, int);
                int jtime = va_arg(vl, int);
                for(lp = throttle_hooks; lp; lp = lp->next)
                {
                    int (*rfunc) (aClient *, aChannel *, int, int, int) = 
                                    ((aHook *)lp->value.cp)->funcptr;
                    if((ret = (*rfunc)(acptr, chptr, type, jnum, jtime)) == FLUSH_BUFFER)
                        break;
                }
                break;
            }

        case CHOOK_FORBID:
            {
                aClient *acptr = va_arg(vl, aClient *);
                char *name = va_arg(vl, char *);
                struct simBan *ban = va_arg(vl, struct simBan *);
                for(lp = forbid_hooks; lp; lp = lp->next)
                {
                    int (*rfunc) (aClient *, char *, struct simBan *) = 
                                    ((aHook *)lp->value.cp)->funcptr;
                    if((ret = (*rfunc)(acptr, name, ban)) == FLUSH_BUFFER)
                        break;
                }
                break;
            }

        case CHOOK_SIGNOFF:
            {
                aClient *acptr = va_arg(vl, aClient *);
                for(lp = signoff_hooks; lp; lp = lp->next)
                {
                    void (*rfunc) (aClient *) = 
                                    ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(acptr);
                }
                break;
            }

        case MHOOK_LOAD:
            {
                char *txtptr = va_arg(vl, char *);
                void *avoid = va_arg(vl, void *);

                for(lp = mload_hooks; lp; lp = lp->next)
                {
                    int (*rfunc) (char *, void *) = 
                                ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(txtptr, avoid);
                }
                break;
            }

        case MHOOK_UNLOAD:
            {
                char *txtptr = va_arg(vl, char *);
                void *avoid = va_arg(vl, void *);
                for(lp = munload_hooks; lp; lp = lp->next)
                {
                    int (*rfunc) (char *, void *) = 
                                  ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(txtptr, avoid);
                }
                break;
            }
      
        default:
            sendto_realops_lev(DEBUG_LEV, "Call for unknown hook type %d", 
                hooktype);
            break;
    }   
    va_end(vl);
    return ret;
}

void 
list_hooks(aClient *sptr)
{
    DLink *lp;

    for(lp = all_hooks; lp; lp = lp->next)
    {
        aHook *hook = (aHook *) lp->value.cp;
        aModule *mod = hook->owner;

        sendto_one(sptr, ":%s NOTICE %s :Module: %s  Type: %s",
                   me.name, sptr->name, mod->name, 
                   get_texthooktype(hook->hooktype));
    }
}

int init_modules()
{
    int i;

    if(!modules)
        return 0;

    for(i = 0; modules->autoload[i]; i++)
    {
        load_module(NULL, modules->autoload[i]);
        printf("Module %s Loaded Successfully.\n", modules->autoload[i]);
    }
    return 0;
}
#endif

u_long
memcount_modules(MCmodules *mc)
{
#ifdef USE_HOOKMODULES
    int      c;
    DLink   *dl;
    aModule *m;
#endif

    mc->file = __FILE__;

#ifdef USE_HOOKMODULES
    for (dl = module_list; dl; dl = dl->next)
    {
        mc->e_dlinks++;
        m = (aModule *)dl->value.cp;
        mc->modules.c++;
        mc->modules.m += sizeof(*m);
        if (m->name)
            mc->modules.m += strlen(m->name) + 1;
        if (m->version)
            mc->modules.m += strlen(m->version) + 1;
        if (m->description)
            mc->modules.m += strlen(m->description) + 1;
    }

    c = mc_dlinks(all_hooks);
    mc->hooks.c = c;
    mc->hooks.m = c * sizeof(aHook);
    mc->e_dlinks += c;

    mc->e_dlinks += mc_dlinks(preaccess_hooks);
    mc->e_dlinks += mc_dlinks(postaccess_hooks);
    mc->e_dlinks += mc_dlinks(postmotd_hooks);
    mc->e_dlinks += mc_dlinks(msg_hooks);
    mc->e_dlinks += mc_dlinks(chanmsg_hooks);
    mc->e_dlinks += mc_dlinks(usermsg_hooks);
    mc->e_dlinks += mc_dlinks(mymsg_hooks);
    mc->e_dlinks += mc_dlinks(every10_hooks);
    mc->e_dlinks += mc_dlinks(join_hooks);
    mc->e_dlinks += mc_dlinks(sendburst_hooks);
    mc->e_dlinks += mc_dlinks(throttle_hooks);
    mc->e_dlinks += mc_dlinks(forbid_hooks);
    mc->e_dlinks += mc_dlinks(signoff_hooks);
    mc->e_dlinks += mc_dlinks(mload_hooks);
    mc->e_dlinks += mc_dlinks(munload_hooks);

    mc->total.c += mc->modules.c + mc->hooks.c;
    mc->total.m += mc->modules.m + mc->hooks.m;

    return mc->total.m;
#else
    return 0;
#endif
}

