#ifndef _IRCD_DOG3_FDLIST
#define _IRCD_DOG3_FDLIST

/* $Id: fdlist.h 1303 2006-12-07 03:23:17Z epiphani $ */

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

#endif /* _IRCD_DOG3_FDLIST */
