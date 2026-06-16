#ifndef _IRCD_DOG3_FDLIST
#define _IRCD_DOG3_FDLIST

typedef struct fdstruct 
{
    int         entry[MAXCONNECTIONS + 2];
    int         last_entry;
#ifdef USE_KQUEUE
    int		kqueue_fd;
#endif
} fdlist;

void        addto_fdlist(int a, fdlist * b);
void        delfrom_fdlist(int a, fdlist * b);
void        init_fdlist(fdlist * b);
void        flush_fdlist_connections(fdlist * listp);

#endif /* _IRCD_DOG3_FDLIST */
