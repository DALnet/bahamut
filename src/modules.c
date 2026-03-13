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
m_module(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
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
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include "mapi.h"
#include "cmds.h"
#include "cap.h"

/* XXX hack.  check on RTLD_NOW later. */
#ifndef RTLD_NOW
#define RTLD_NOW 0
#endif

DLink *module_list = NULL;
void *module_reload_state = NULL;

typedef struct loaded_module
{
    char *name;

    char *version;
    char *description;
    char *mod_path;    /* full filesystem path to the .so file */

    void *handle;

    /* MAPI v1 fields (is_mapi == 1) */
    int                  is_mapi;   /* 1 if this is a MAPI v1 module     */
    struct mapi_module  *mheader;   /* points into the loaded .so memory  */

    /* Old-style module symbols (is_mapi == 0) */
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
void *bircmodule_add_hook(enum c_hooktype, void *, void *);

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
        const char *flags = "";

        if (mod->is_mapi && (mod->mheader->mod_flags & MAPI_CORE))
            flags = "  [core]";

        sendto_one(sptr, ":%s NOTICE %s :Module: %-20s ver %-8s%s",
                   me.name, sptr->name, mod->name, mod->version, flags);

        sendto_one(sptr, ":%s NOTICE %s :  - %s", me.name, sptr->name,
                   mod->description);
    }
}

void
destroy_module(aModule *themod)
{
    if (themod->is_mapi)
    {
        /* Call mapi_unregister callback before unregistering commands */
        if (themod->mheader->mapi_unregister)
            themod->mheader->mapi_unregister();

        /* Unregister IRCv3 capabilities before closing the .so */
        if (themod->mheader->caps)
        {
            const struct mapi_cap_av1 *cap;
            for (cap = themod->mheader->caps; cap->name; cap++)
                cap_del(cap->name);
        }

        /* Unregister all MAPI-registered commands before closing the .so */
        if (themod->mheader->cmds)
        {
            const struct mapi_cmd_av2 *c;
            for (c = themod->mheader->cmds; c->cmd; c++)
                cmd_del(c->cmd);
        }
    }
    else
    {
        (*themod->module_shutdown)();
    }

    dlclose(themod->handle);
    bircmodule_free(themod->mod_path);
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
    char mnamebuf[PATH_MAX];
    char regname[256];   /* registered module name (basename, no .so ext) */
    struct mapi_module *mheader;
    char *ver, *desc;
    int acsz = -1, ret;
    const char *base;
    char *dot;

    /*
     * Determine the full library path (mnamebuf) and the short registered
     * name (regname) used for find_module() and module_list storage.
     *
     * If modname begins with '/' it is already a full path (e.g. when called
     * by load_module_dir).  Otherwise construct the path from the module
     * search directory.
     */
    if (modname[0] == '/')
    {
        /* Full path supplied — extract basename without .so as regname */
        strncpy(mnamebuf, modname, sizeof(mnamebuf) - 1);
        mnamebuf[sizeof(mnamebuf) - 1] = '\0';

        base = strrchr(modname, '/');
        base = base ? base + 1 : modname;
        strncpy(regname, base, sizeof(regname) - 1);
        regname[sizeof(regname) - 1] = '\0';
        dot = strrchr(regname, '.');
        if (dot)
            *dot = '\0';
    }
    else
    {
        strncpy(regname, modname, sizeof(regname) - 1);
        regname[sizeof(regname) - 1] = '\0';

        if (modules && modules->module_path)
            ircsnprintf(mnamebuf, sizeof(mnamebuf), "%s/%s.so",
                        modules->module_path, modname);
        else
            ircsnprintf(mnamebuf, sizeof(mnamebuf), "%s/modules/%s.so",
                        dpath, modname);
    }

    if ((themod = find_module(regname)))
    {
        if (sptr)
            sendto_one(sptr, ":%s NOTICE %s :Module %s is already loaded"
                       " [version: %s]", me.name, sptr->name, regname,
                       themod->version);
        else
            fprintf(stderr, " - Module %s is already loaded [version: %s]\n",
                    regname, themod->version);
        return 0;
    }

    memset(&tmpmod, 0, sizeof(tmpmod));
    tmpmod.handle = dlopen(mnamebuf, RTLD_NOW);
    if (tmpmod.handle == NULL)
    {
        if (sptr)
            sendto_one(sptr, ":%s NOTICE %s :Module load error for %s: %s",
                       me.name, sptr->name, regname, dlerror());
        else
            fprintf(stderr, " - Module load error for %s: %s\n",
                    regname, dlerror());
        return -1;
    }

    tmpmod.mod_path = bircmodule_strdup(mnamebuf);

    /* ---------------------------------------------------------------
     * Try MAPI v2/v3: look for the "_mheader" symbol.
     * --------------------------------------------------------------- */
    dlerror();
    mheader = (struct mapi_module *) dlsym(tmpmod.handle, "_mheader");

    if (mheader != NULL)
    {
        /* Accept MAPI v2 and v3 modules */
        if (mheader->mapi_version != MAPI_VERSION_3
            && mheader->mapi_version != MAPI_VERSION_2)
        {
            if (sptr)
                sendto_one(sptr, ":%s NOTICE %s :Module load error for %s:"
                           " Incompatible MAPI version (server: %d module: %d)",
                           me.name, sptr->name, regname,
                           MAPI_VERSION, mheader->mapi_version);
            else
                fprintf(stderr, " - Module load error for %s: Incompatible MAPI"
                                " version (server: %d module: %d)\n",
                        regname, MAPI_VERSION, mheader->mapi_version);
            dlclose(tmpmod.handle);
            bircmodule_free(tmpmod.mod_path);
            return -1;
        }

        /* ABI version check (v3+ modules only) */
        if (mheader->mapi_version >= MAPI_VERSION_3
            && mheader->min_abi_version > IRCD_ABI_VERSION)
        {
            if (sptr)
                sendto_one(sptr, ":%s NOTICE %s :Module load error for %s:"
                           " Requires ABI version %d (server has %d)",
                           me.name, sptr->name, regname,
                           mheader->min_abi_version, IRCD_ABI_VERSION);
            else
                fprintf(stderr, " - Module load error for %s: Requires ABI"
                                " version %d (server has %d)\n",
                        regname, mheader->min_abi_version, IRCD_ABI_VERSION);
            dlclose(tmpmod.handle);
            bircmodule_free(tmpmod.mod_path);
            return -1;
        }

        tmpmod.is_mapi  = 1;
        tmpmod.mheader  = mheader;
        tmpmod.name     = bircmodule_strdup((char *)(mheader->name
                                ? mheader->name : regname));
        tmpmod.version  = bircmodule_strdup((char *)(mheader->version
                                ? mheader->version : "<unknown>"));
        tmpmod.description = bircmodule_strdup((char *)(mheader->description
                                ? mheader->description : ""));

        themod = (aModule *) bircmodule_malloc(sizeof(aModule));
        memcpy(themod, &tmpmod, sizeof(aModule));
        /* Add to list before registering hooks so bircmodule_add_hook can
         * find the owner via find_module_opaque(). */
        add_to_list(&module_list, themod);

        /* Register IRC commands (MAPI v2: mapi_cmd_av2) */
        if (mheader->cmds)
        {
            const struct mapi_cmd_av2 *c;
            for (c = mheader->cmds; c->cmd; c++)
            {
                if (cmd_add(c) < 0)
                {
                    if (sptr)
                        sendto_one(sptr, ":%s NOTICE %s :Warning: command %s"
                                   " from module %s already registered",
                                   me.name, sptr->name, c->cmd, regname);
                    else
                        fprintf(stderr, " - Warning: command %s from module"
                                        " %s already registered\n",
                                c->cmd, regname);
                }
            }
        }

        /* Register hooks */
        if (mheader->hooks)
        {
            const struct mapi_hook_av1 *h;
            for (h = mheader->hooks; h->fn; h++)
                bircmodule_add_hook(h->hooktype, (void *) themod, h->fn);
        }

        /* Register IRCv3 capabilities */
        if (mheader->caps)
        {
            const struct mapi_cap_av1 *cap;
            for (cap = mheader->caps; cap->name; cap++)
                cap_add(cap);
        }

        /* Call mapi_register callback if provided */
        if (mheader->mapi_register)
            mheader->mapi_register();

        if (sptr)
            sendto_one(sptr, ":%s NOTICE %s :Module %s (MAPI) successfully"
                       " loaded [version: %s]",
                       me.name, sptr->name, regname, themod->version);
        else
            fprintf(stderr, " - Module %s (MAPI) successfully loaded"
                            " [version: %s]\n", regname, themod->version);

        call_hooks(MHOOK_LOAD, regname, (void *) themod);
        return 0;
    }

    /* ---------------------------------------------------------------
     * Old-style module (backward compatibility).
     * --------------------------------------------------------------- */
    /* modsym_load calls dlclose on failure, but we must free mod_path too */
    if (!modsym_load(sptr, regname, "bircmodule_check", tmpmod.handle,
                     (void *) &tmpmod.module_check))
    { bircmodule_free(tmpmod.mod_path); return -1; }
    if (!modsym_load(sptr, regname, "bircmodule_init", tmpmod.handle,
                     (void *) &tmpmod.module_init))
    { bircmodule_free(tmpmod.mod_path); return -1; }
    if (!modsym_load(sptr, regname, "bircmodule_shutdown", tmpmod.handle,
                     (void *) &tmpmod.module_shutdown))
    { bircmodule_free(tmpmod.mod_path); return -1; }
    if (!modsym_load(sptr, regname, "bircmodule_getinfo", tmpmod.handle,
                     (void *) &tmpmod.module_getinfo))
    { bircmodule_free(tmpmod.mod_path); return -1; }
    if (!modsym_load(sptr, regname, "bircmodule_command", tmpmod.handle,
                     (void *) &tmpmod.module_command))
    { bircmodule_free(tmpmod.mod_path); return -1; }
    if (!modsym_load(sptr, regname, "bircmodule_globalcommand", tmpmod.handle,
                     (void *) &tmpmod.module_globalcommand))
    { bircmodule_free(tmpmod.mod_path); return -1; }

    (*tmpmod.module_check)(&acsz);
    if (acsz != MODULE_INTERFACE_VERSION)
    {
        if (sptr)
            sendto_one(sptr, ":%s NOTICE %s :Module load error for %s:"
                       " Incompatible module (My interface version: %d"
                       " Module version: %d)",
                       me.name, sptr->name, regname,
                       MODULE_INTERFACE_VERSION, acsz);
        else
            fprintf(stderr, " - Module load error for %s: Incompatible module"
                            " (My: %d Module: %d)\n",
                    regname, MODULE_INTERFACE_VERSION, acsz);
        dlclose(tmpmod.handle);
        bircmodule_free(tmpmod.mod_path);
        return -1;
    }

    tmpmod.name = bircmodule_strdup(regname);

    ver = desc = NULL;
    (*tmpmod.module_getinfo)(&ver, &desc);
    tmpmod.version = bircmodule_strdup((ver != NULL) ? ver : "<no version>");
    tmpmod.description = bircmodule_strdup((desc != NULL) ? desc :
                                                            "<no description>");
    themod = (aModule *) bircmodule_malloc(sizeof(aModule));
    memcpy(themod, &tmpmod, sizeof(aModule));
    add_to_list(&module_list, themod);

    ret = (*themod->module_init)((void *) themod);

    if (ret == 0)
    {
        if (sptr)
            sendto_one(sptr, ":%s NOTICE %s :Module %s successfully loaded"
                       " [version: %s]", me.name, sptr->name, regname,
                       themod->version);
        else
            fprintf(stderr, " - Module %s successfully loaded [version: %s]\n",
                    regname, themod->version);

        call_hooks(MHOOK_LOAD, regname, (void *) themod);
    }
    else
    {
        drop_all_hooks(themod);
        destroy_module(themod);

        if (sptr)
            sendto_one(sptr, ":%s NOTICE %s :Module %s load failed (module"
                       " requested unload)", me.name, sptr->name, regname);
        else
            fprintf(stderr, " - Module %s load failed (module requested"
                            " unload)\n", regname);
    }
    return 0;
}

int
unload_module(aClient *sptr, char *modname)
{
    aModule *themod = find_module(modname);

    if (!themod)
    {
        sendto_one(sptr, ":%s NOTICE %s :Module %s is not loaded",
                   me.name, sptr->name, modname);
        return 0;
    }

    /* Refuse to unload MAPI core modules */
    if (themod->is_mapi && (themod->mheader->mod_flags & MAPI_CORE))
    {
        sendto_one(sptr, ":%s NOTICE %s :Cannot unload core module %s",
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
reload_module(aClient *sptr, char *modname)
{
    aModule *themod = find_module(modname);
    char saved_path[PATH_MAX];

    if (!themod)
    {
        sendto_one(sptr, ":%s NOTICE %s :Module %s is not loaded",
                   me.name, sptr->name, modname);
        return 0;
    }

    /* Only MAPI modules support reload */
    if (!themod->is_mapi)
    {
        sendto_one(sptr, ":%s NOTICE %s :Cannot reload non-MAPI module %s",
                   me.name, sptr->name, modname);
        return 0;
    }

    /* Save the path before we destroy the module */
    strncpy(saved_path, themod->mod_path, sizeof(saved_path) - 1);
    saved_path[sizeof(saved_path) - 1] = '\0';

    /* Call serialize callback if available (v3+ only) */
    if (themod->mheader->mapi_version >= MAPI_VERSION_3
        && themod->mheader->mapi_serialize)
        themod->mheader->mapi_serialize();

    /* Tear down the old instance */
    drop_all_hooks(themod);
    call_hooks(MHOOK_UNLOAD, themod->name, (void *) themod);
    destroy_module(themod);

    /* Load the new instance from the same path */
    if (load_module(sptr, saved_path) < 0)
    {
        sendto_one(sptr, ":%s NOTICE %s :Reload of %s failed — module"
                   " is now unloaded", me.name, sptr->name, modname);
        return -1;
    }

    /* Call deserialize callback on the freshly loaded module */
    themod = find_module(modname);
    if (themod && themod->is_mapi
        && themod->mheader->mapi_version >= MAPI_VERSION_3
        && themod->mheader->mapi_deserialize)
        themod->mheader->mapi_deserialize();

    sendto_one(sptr, ":%s NOTICE %s :Module %s successfully reloaded",
               me.name, sptr->name, modname);

    return 0;
}

void
info_module(aClient *sptr, char *modname)
{
    aModule *themod = find_module(modname);

    if (!themod)
    {
        sendto_one(sptr, ":%s NOTICE %s :Module %s is not loaded",
                   me.name, sptr->name, modname);
        return;
    }

    sendto_one(sptr, ":%s NOTICE %s :--- Module info for %s ---",
               me.name, sptr->name, themod->name);
    sendto_one(sptr, ":%s NOTICE %s :  Version:     %s",
               me.name, sptr->name, themod->version);
    sendto_one(sptr, ":%s NOTICE %s :  Description: %s",
               me.name, sptr->name, themod->description);

    if (themod->is_mapi)
    {
        int mver = themod->mheader->mapi_version;

        sendto_one(sptr, ":%s NOTICE %s :  MAPI version: %d",
                   me.name, sptr->name, mver);
        sendto_one(sptr, ":%s NOTICE %s :  Flags:        %s",
                   me.name, sptr->name,
                   (themod->mheader->mod_flags & MAPI_CORE) ? "CORE" : "none");

        if (mver >= MAPI_VERSION_3)
        {
            sendto_one(sptr, ":%s NOTICE %s :  Min ABI:      %d (server: %d)",
                       me.name, sptr->name,
                       themod->mheader->min_abi_version, IRCD_ABI_VERSION);
            sendto_one(sptr, ":%s NOTICE %s :  Serialize:    %s",
                       me.name, sptr->name,
                       themod->mheader->mapi_serialize ? "yes" : "no");
        }
        else
        {
            sendto_one(sptr, ":%s NOTICE %s :  (MAPI v2 — no ABI/serialize info)",
                       me.name, sptr->name);
        }
    }
    else
    {
        sendto_one(sptr, ":%s NOTICE %s :  Type: legacy (non-MAPI)",
                   me.name, sptr->name);
    }

    sendto_one(sptr, ":%s NOTICE %s :  Path:        %s",
               me.name, sptr->name,
               themod->mod_path ? themod->mod_path : "<unknown>");
    sendto_one(sptr, ":%s NOTICE %s :--- End of module info ---",
               me.name, sptr->name);
}

int
m_module(struct MsgBuf *msgbuf, aClient *cptr, aClient *sptr, int parc, char *parv[])
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
    else if(mycmp(parv[1], "RELOAD") == 0)
    {
        if(!(MyClient(sptr) && IsAdmin(sptr)))
        {
            sendto_one(sptr, err_str(ERR_NOPRIVILEGES), me.name, parv[0]);
            return 0;
        }
        if(!BadPtr(parv[2]))
            reload_module(sptr, parv[2]);
        else
        {
            sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name,
                       parv[0], "MODULE");
            return 0;
        }
    }
    else if(mycmp(parv[1], "INFO") == 0)
    {
        if(!BadPtr(parv[2]))
            info_module(sptr, parv[2]);
        else
        {
            sendto_one(sptr, err_str(ERR_NEEDMOREPARAMS), me.name,
                       parv[0], "MODULE");
            return 0;
        }
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
static DLink *onaccess_hooks = NULL;
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
static DLink *whois_hooks = NULL;
static DLink *maskhost_hooks = NULL;
static DLink *floodwarn_hooks = NULL;
static DLink *spamwarn_hooks = NULL;
static DLink *signoff_hooks = NULL;
static DLink *mload_hooks = NULL;
static DLink *munload_hooks = NULL;
static DLink *postregister_hooks = NULL;
static DLink *away_hooks         = NULL;
static DLink *postdispatch_hooks = NULL;
static DLink *invite_hooks       = NULL;
static DLink *setname_hooks      = NULL;
static DLink *tagmsg_hooks       = NULL;
static DLink *nick_hooks         = NULL;
static DLink *part_hooks         = NULL;
static DLink *chanmode_hooks     = NULL;
static DLink *topic_hooks        = NULL;
static DLink *umode_hooks        = NULL;
static DLink *account_login_hooks  = NULL;
static DLink *account_logout_hooks = NULL;
static DLink *postjoin_hooks       = NULL;
static DLink *chghost_hooks        = NULL;

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

        case CHOOK_ONACCESS:
            return "On-access";

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

        case CHOOK_WHOIS:
            return "whois";

        case CHOOK_MASKHOST:
            return "Mask Host";

        case CHOOK_FLOODWARN:
            return "FloodWarn";

        case CHOOK_SPAMWARN:
            return "SpamWarn";

        case CHOOK_SIGNOFF:
            return "Signoff";

        case MHOOK_LOAD:
            return "Module load";

        case MHOOK_UNLOAD:
            return "Module unload";

        case CHOOK_POSTREGISTER:
            return "Post-register";

        case CHOOK_AWAY:
            return "Away";

        case CHOOK_POSTDISPATCH:
            return "Post-dispatch";

        case CHOOK_INVITE:
            return "Invite";

        case CHOOK_SETNAME:
            return "Setname";

        case CHOOK_TAGMSG:
            return "TagMsg";

        case CHOOK_NICK:
            return "Nick";

        case CHOOK_PART:
            return "Part";

        case CHOOK_CHANMODE:
            return "ChanMode";

        case CHOOK_TOPIC:
            return "Topic";

        case CHOOK_UMODE:
            return "Umode";

        case CHOOK_ACCOUNT_LOGIN:
            return "AccountLogin";
        case CHOOK_ACCOUNT_LOGOUT:
            return "AccountLogout";
        case CHOOK_POSTJOIN:
            return "PostJoin";
        case CHOOK_CHGHOST:
            return "ChgHost";

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

        case CHOOK_ONACCESS:
            hooklist = &onaccess_hooks;
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

        case CHOOK_WHOIS:
            hooklist = &whois_hooks;
            break;

        case CHOOK_MASKHOST:
            hooklist = &maskhost_hooks;
            break;

        case CHOOK_FLOODWARN:
            hooklist = &floodwarn_hooks;
            break;

        case CHOOK_SPAMWARN:
            hooklist = &spamwarn_hooks;
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

        case CHOOK_POSTREGISTER:
            hooklist = &postregister_hooks;
            break;

        case CHOOK_AWAY:
            hooklist = &away_hooks;
            break;

        case CHOOK_POSTDISPATCH:
            hooklist = &postdispatch_hooks;
            break;

        case CHOOK_INVITE:
            hooklist = &invite_hooks;
            break;

        case CHOOK_SETNAME:
            hooklist = &setname_hooks;
            break;

        case CHOOK_TAGMSG:
            hooklist = &tagmsg_hooks;
            break;

        case CHOOK_NICK:
            hooklist = &nick_hooks;
            break;

        case CHOOK_PART:
            hooklist = &part_hooks;
            break;

        case CHOOK_CHANMODE:
            hooklist = &chanmode_hooks;
            break;

        case CHOOK_TOPIC:
            hooklist = &topic_hooks;
            break;

        case CHOOK_UMODE:
            hooklist = &umode_hooks;
            break;

        case CHOOK_ACCOUNT_LOGIN:
            hooklist = &account_login_hooks;
            break;
        case CHOOK_ACCOUNT_LOGOUT:
            hooklist = &account_logout_hooks;
            break;
        case CHOOK_POSTJOIN:
            hooklist = &postjoin_hooks;
            break;
        case CHOOK_CHGHOST:
            hooklist = &chghost_hooks;
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

        case CHOOK_ONACCESS:
            {
                aClient *acptr = va_arg(vl, aClient *);
                char *username = va_arg(vl, char *);
                char *host = va_arg(vl, char *);
                char *server = va_arg(vl, char *);
                char *realname = va_arg(vl, char *);

                for(lp = onaccess_hooks; lp; lp = lp->next)
                {
                    int (*rfunc) (aClient *, char *, char *, char *, char *) =
                                    ((aHook *)lp->value.cp)->funcptr;
                    if((ret = (*rfunc)(acptr, username, host, server, realname)) == FLUSH_BUFFER)
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

        case CHOOK_WHOIS:
            {
                aClient *sptr = va_arg(vl, aClient *);
                aClient *acptr = va_arg(vl, aClient *);
                for(lp = whois_hooks; lp; lp = lp->next)
                {
                    int (*rfunc) (aClient *, aClient *) = 
                                    ((aHook *)lp->value.cp)->funcptr;
                    if((ret = (*rfunc)(sptr, acptr)) == FLUSH_BUFFER)
                        break;
                }
                break;
            }


        case CHOOK_MASKHOST:
            {
                char *orghost = va_arg(vl, char *);
                char *orgip = va_arg(vl, char *);
                char *newhost = va_arg(vl, char *);
                int type = va_arg(vl, int);
                for(lp = maskhost_hooks; lp; lp = lp->next)
                {
                    int (*rfunc) (char *, char *, char **, int) = 
                                    ((aHook *)lp->value.cp)->funcptr;
                    /* Possible results by the module:
                       1 (UHM_SUCCESS)                      = Success, the host has been masked (so don't try other modules).
                       0 (UHM_SOFT_FAILURE)                 = Failure, the host wasn't masked but try other modules (maybe they will mask the host).
                       -2 (UHM_HARD_FAILURE / FLUSH_BUFFER) = Failure, the host wasn't masked but *don't* try other modules.
                     */
                    if((ret = (*rfunc)(orghost, orgip, &newhost, type)) != UHM_SOFT_FAILURE)
                        break; /* We stop trying other modules if we get UHM_SUCCESS or UHM_HARD_FAILURE */
                }
                break;
            }

        case CHOOK_FLOODWARN:
            {
                aClient *sptr = va_arg(vl, aClient *);
                aChannel *chptr = va_arg(vl, aChannel *);
                int type = va_arg(vl, int);
                char *cmd = va_arg(vl, char *);
                char *reason = va_arg(vl, char *);
                for(lp = floodwarn_hooks; lp; lp = lp->next)
                {
                    int (*rfunc) (aClient *, aChannel *, int, char *, char *) = 
                                    ((aHook *)lp->value.cp)->funcptr;
                    if((ret = (*rfunc)(sptr, chptr, type, cmd, reason)) == FLUSH_BUFFER)
                        break;
                }
                break;
            }

        case CHOOK_SPAMWARN:
            {
                aClient *sptr = va_arg(vl, aClient *);
                int type = va_arg(vl, int);
                int max_targets = va_arg(vl, int);
                char *target_name = va_arg(vl, char *);
                for(lp = spamwarn_hooks; lp; lp = lp->next)
                {
                    int (*rfunc) (aClient *, int, int, char *) = 
                                    ((aHook *)lp->value.cp)->funcptr;
                    if((ret = (*rfunc)(sptr, type, max_targets, target_name)) == FLUSH_BUFFER)
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
      
        case CHOOK_POSTREGISTER:
            {
                aClient *acptr = va_arg(vl, aClient *);
                for(lp = postregister_hooks; lp; lp = lp->next)
                {
                    int (*rfunc)(aClient *) = ((aHook *)lp->value.cp)->funcptr;
                    if((ret = (*rfunc)(acptr)) == FLUSH_BUFFER)
                        break;
                }
                break;
            }

        case CHOOK_AWAY:
            {
                aClient *acptr   = va_arg(vl, aClient *);
                int      setting = va_arg(vl, int);
                char    *msg     = va_arg(vl, char *);
                for(lp = away_hooks; lp; lp = lp->next)
                {
                    void (*rfunc)(aClient *, int, char *) =
                                    ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(acptr, setting, msg);
                }
                break;
            }

        case CHOOK_POSTDISPATCH:
            {
                aClient *acptr = va_arg(vl, aClient *);
                for(lp = postdispatch_hooks; lp; lp = lp->next)
                {
                    int (*rfunc)(aClient *) = ((aHook *)lp->value.cp)->funcptr;
                    if((ret = (*rfunc)(acptr)) == FLUSH_BUFFER)
                        break;
                }
                break;
            }

        case CHOOK_INVITE:
            {
                aClient  *inviter = va_arg(vl, aClient *);
                aClient  *target  = va_arg(vl, aClient *);
                aChannel *chptr   = va_arg(vl, aChannel *);
                for(lp = invite_hooks; lp; lp = lp->next)
                {
                    void (*rfunc)(aClient *, aClient *, aChannel *) =
                                    ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(inviter, target, chptr);
                }
                break;
            }

        case CHOOK_SETNAME:
            {
                aClient    *acptr   = va_arg(vl, aClient *);
                const char *newname = va_arg(vl, const char *);
                for(lp = setname_hooks; lp; lp = lp->next)
                {
                    void (*rfunc)(aClient *, const char *) =
                                    ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(acptr, newname);
                }
                break;
            }

        case CHOOK_TAGMSG:
            {
                aClient    *acptr   = va_arg(vl, aClient *);
                void       *target  = va_arg(vl, void *);
                int         is_chan = va_arg(vl, int);
                const char *tags    = va_arg(vl, const char *);
                for(lp = tagmsg_hooks; lp; lp = lp->next)
                {
                    void (*rfunc)(aClient *, void *, int, const char *) =
                                    ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(acptr, target, is_chan, tags);
                }
                break;
            }

        case CHOOK_NICK:
            {
                aClient    *acptr   = va_arg(vl, aClient *);
                const char *oldnick = va_arg(vl, const char *);
                const char *newnick = va_arg(vl, const char *);
                for(lp = nick_hooks; lp; lp = lp->next)
                {
                    void (*rfunc)(aClient *, const char *, const char *) =
                                    ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(acptr, oldnick, newnick);
                }
                break;
            }

        case CHOOK_PART:
            {
                aClient    *acptr  = va_arg(vl, aClient *);
                aChannel   *chptr  = va_arg(vl, aChannel *);
                const char *reason = va_arg(vl, const char *);
                for(lp = part_hooks; lp; lp = lp->next)
                {
                    void (*rfunc)(aClient *, aChannel *, const char *) =
                                    ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(acptr, chptr, reason);
                }
                break;
            }

        case CHOOK_CHANMODE:
            {
                aClient    *acptr   = va_arg(vl, aClient *);
                aChannel   *chptr   = va_arg(vl, aChannel *);
                const char *modebuf = va_arg(vl, const char *);
                const char *parabuf = va_arg(vl, const char *);
                for(lp = chanmode_hooks; lp; lp = lp->next)
                {
                    void (*rfunc)(aClient *, aChannel *, const char *,
                                  const char *) =
                                    ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(acptr, chptr, modebuf, parabuf);
                }
                break;
            }

        case CHOOK_TOPIC:
            {
                aClient    *acptr = va_arg(vl, aClient *);
                aChannel   *chptr = va_arg(vl, aChannel *);
                const char *topic = va_arg(vl, const char *);
                for(lp = topic_hooks; lp; lp = lp->next)
                {
                    void (*rfunc)(aClient *, aChannel *, const char *) =
                                    ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(acptr, chptr, topic);
                }
                break;
            }

        case CHOOK_UMODE:
            {
                aClient       *acptr    = va_arg(vl, aClient *);
                unsigned long  setflags = va_arg(vl, unsigned long);
                for(lp = umode_hooks; lp; lp = lp->next)
                {
                    void (*rfunc)(aClient *, unsigned long) =
                                    ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(acptr, setflags);
                }
                break;
            }

        case CHOOK_ACCOUNT_LOGIN:
            {
                aClient *acptr = va_arg(vl, aClient *);
                for(lp = account_login_hooks; lp; lp = lp->next)
                {
                    void (*rfunc)(aClient *) =
                                    ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(acptr);
                }
                break;
            }

        case CHOOK_ACCOUNT_LOGOUT:
            {
                aClient *acptr = va_arg(vl, aClient *);
                for(lp = account_logout_hooks; lp; lp = lp->next)
                {
                    void (*rfunc)(aClient *) =
                                    ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(acptr);
                }
                break;
            }

        case CHOOK_POSTJOIN:
            {
                aClient *acptr = va_arg(vl, aClient *);
                aChannel *chptr = va_arg(vl, aChannel *);
                for(lp = postjoin_hooks; lp; lp = lp->next)
                {
                    void (*rfunc)(aClient *, aChannel *) =
                                    ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(acptr, chptr);
                }
                break;
            }

        case CHOOK_CHGHOST:
            {
                aClient    *acptr    = va_arg(vl, aClient *);
                const char *old_user = va_arg(vl, const char *);
                const char *old_host = va_arg(vl, const char *);
                for(lp = chghost_hooks; lp; lp = lp->next)
                {
                    void (*rfunc)(aClient *, const char *, const char *) =
                                    ((aHook *)lp->value.cp)->funcptr;
                    (*rfunc)(acptr, old_user, old_host);
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

/*
 * load_module_dir - load all *.so files from a directory.
 *
 * Called at startup (core modules directory) and optionally by config.
 * Each file is loaded via load_module(); MAPI modules declare their own
 * mod_flags (e.g. MAPI_CORE) inside the .so.
 */
void
load_module_dir(const char *dir_path)
{
    DIR *dir;
    struct dirent *ent;
    char filepath[PATH_MAX];
    size_t nlen;

    dir = opendir(dir_path);
    if (!dir)
    {
        fprintf(stderr, " - Warning: cannot open module directory %s: %s\n",
                dir_path, strerror(errno));
        return;
    }

    while ((ent = readdir(dir)) != NULL)
    {
        nlen = strlen(ent->d_name);
        if (nlen > 3 && strcmp(ent->d_name + nlen - 3, ".so") == 0)
        {
            ircsnprintf(filepath, sizeof(filepath), "%s/%s", dir_path,
                        ent->d_name);
            load_module(NULL, filepath);
        }
    }

    closedir(dir);
}

int init_modules()
{
    int i;
    char corepath[PATH_MAX];

    /* Load core modules first — they must be present before config runs */
    ircsnprintf(corepath, sizeof(corepath), "%s/modules/core", dpath);
    load_module_dir(corepath);

    if (!modules)
        return 0;

    for (i = 0; modules->autoload[i]; i++)
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
    mc->e_dlinks += mc_dlinks(onaccess_hooks);
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
    mc->e_dlinks += mc_dlinks(whois_hooks);
    mc->e_dlinks += mc_dlinks(maskhost_hooks);
    mc->e_dlinks += mc_dlinks(floodwarn_hooks);
    mc->e_dlinks += mc_dlinks(spamwarn_hooks);
    mc->e_dlinks += mc_dlinks(signoff_hooks);
    mc->e_dlinks += mc_dlinks(mload_hooks);
    mc->e_dlinks += mc_dlinks(munload_hooks);
    mc->e_dlinks += mc_dlinks(postregister_hooks);
    mc->e_dlinks += mc_dlinks(away_hooks);
    mc->e_dlinks += mc_dlinks(postdispatch_hooks);
    mc->e_dlinks += mc_dlinks(invite_hooks);
    mc->e_dlinks += mc_dlinks(setname_hooks);
    mc->e_dlinks += mc_dlinks(tagmsg_hooks);
    mc->e_dlinks += mc_dlinks(nick_hooks);
    mc->e_dlinks += mc_dlinks(part_hooks);
    mc->e_dlinks += mc_dlinks(chanmode_hooks);
    mc->e_dlinks += mc_dlinks(topic_hooks);
    mc->e_dlinks += mc_dlinks(umode_hooks);
    mc->e_dlinks += mc_dlinks(account_login_hooks);
    mc->e_dlinks += mc_dlinks(account_logout_hooks);
    mc->e_dlinks += mc_dlinks(postjoin_hooks);
    mc->e_dlinks += mc_dlinks(chghost_hooks);

    mc->total.c += mc->modules.c + mc->hooks.c;
    mc->total.m += mc->modules.m + mc->hooks.m;

    return mc->total.m;
#else
    return 0;
#endif
}

