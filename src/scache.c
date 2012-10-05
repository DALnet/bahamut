#include "struct.h"
#include "common.h"
#include "sys.h"
#include "numeric.h"
#include "h.h"
#include "memcount.h"

static int  hash(char *);	/* keep it hidden here */
/*
 * ircd used to store full servernames in anUser as well as in the
 * whowas info.  there can be some 40k such structures alive at any
 * given time, while the number of unique server names a server sees in
 * its lifetime is at most a few hundred.  by tokenizing server names
 * internally, the server can easily save 2 or 3 megs of RAM.
 * -orabidoo
 */
/*
 * I could have tucked this code into hash.c I suppose but lets keep it
 * separate for now -Dianora
 */

#define SCACHE_HASH_SIZE 257

typedef struct scache_entry
{
    char        name[HOSTLEN + 1];
    struct scache_entry *next;
} SCACHE;

static SCACHE *scache_hash[SCACHE_HASH_SIZE];

/* renamed to keep it consistent with the other hash functions -Dianora */
/* orabidoo had named it init_scache_hash(); */

void clear_scache_hash_table(void)
{
    memset((char *) scache_hash, '\0', sizeof(scache_hash));
}

static int hash(char *string)
{
    int         hash_value;
   
    hash_value = 0;
    while (*string)
	hash_value += (*string++ & 0xDF);

    return hash_value % SCACHE_HASH_SIZE;
}

/*
 * this takes a server name, and returns a pointer to the same string
 * (up to case) in the server name token list, adding it to the list if
 * it's not there.  care must be taken not to call this with
 * user-supplied arguments that haven't been verified to be a valid,
 * existing, servername.  use the hash in list.c for those.  -orabidoo
 */
char *find_or_add(char *name)
{
    int         hash_index;
    SCACHE     *ptr, *newptr;

    ptr = scache_hash[hash_index = hash(name)];
    while (ptr) 
    {
	if (!mycmp(ptr->name, name))
	    return (ptr->name);
	else
	    ptr = ptr->next;
    }

    /* not found -- add it */
    if ((ptr = scache_hash[hash_index])) 
    {
	newptr = scache_hash[hash_index] = (SCACHE *) MyMalloc(sizeof(SCACHE));
	strncpyzt(newptr->name, name, HOSTLEN);
	newptr->next = ptr;
	return (newptr->name);
    }
    else
    {
	ptr = scache_hash[hash_index] = (SCACHE *) MyMalloc(sizeof(SCACHE));
	strncpyzt(ptr->name, name, HOSTLEN);
	ptr->next = (SCACHE *) NULL;
	return (ptr->name);
    }
}

/* list all server names in scache very verbose */

void list_scache(aClient *cptr, aClient *sptr, int parc, char *parv[])
{
    int         hash_index;
    SCACHE     *ptr;

    for (hash_index = 0; hash_index < SCACHE_HASH_SIZE; hash_index++) 
    {
	ptr = scache_hash[hash_index];
	while (ptr) 
	{
	    if (ptr->name)
		sendto_one(sptr, ":%s NOTICE %s :%s",
			   me.name, parv[0], ptr->name);
	    ptr = ptr->next;
	}
    }
}

u_long
memcount_scache(MCscache *mc)
{
    SCACHE *ce;
    size_t i;

    mc->file = __FILE__;

    for (i = 0; i < sizeof(scache_hash)/sizeof(scache_hash[0]); i++)
    {
        for (ce = scache_hash[i]; ce; ce = ce->next)
        {
            mc->cached.c++;
            mc->cached.m += sizeof(*ce);
        }
    }

    mc->s_hash.c = sizeof(scache_hash)/sizeof(scache_hash[0]);
    mc->s_hash.m = sizeof(scache_hash);

    mc->total.c += mc->cached.c;
    mc->total.m += mc->cached.m;

    return mc->total.m;
}

