/************************************************************************
 *   IRC - Internet Relay Chat, src/socketengine_epoll.c
 *   Copyright (C) 2004 David Parton
 *
 * engine functions for the /dev/epoll socket engine
 *
 */
 
 /* $Id$ */


#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "fds.h"

#include <stdint.h>
#include <errno.h>
#include <sys/epoll.h>

#ifdef NEED_EPOLL_DEFS
#include <asm/unistd.h>

_syscall1(int, epoll_create, int, size)
_syscall4(int, epoll_ctl, int, epfd, int, op, int, fd, struct epoll_event*, event)
_syscall4(int, epoll_wait, int, epfd, struct epoll_event*, pevents, int, maxevents, int, timeout)

#endif

static int epoll_id = -1, numfds = 0;
static struct epoll_fd
{
    int       fd;
    unsigned int events;
} epoll_fds[MAXCONNECTIONS]; 


void engine_init()
{
    epoll_id = epoll_create(MAXCONNECTIONS);
    memset(epoll_fds, 0, sizeof(epoll_fds));
}

void engine_add_fd(int fd)
{
    struct epoll_event ev;
    
    if (numfds >= MAXCONNECTIONS)
        abort();
    
    ev.events = 0;
    ev.data.ptr = &epoll_fds[numfds];
    if (epoll_ctl(epoll_id, EPOLL_CTL_ADD, fd, &ev) < 0)
        abort();
    
    epoll_fds[numfds].fd = fd;
    epoll_fds[numfds].events = 0;
    set_fd_internal(fd, (void*)&epoll_fds[numfds]);
    ++numfds;
}

void engine_del_fd(int fd)
{
    struct epoll_event ev;
    struct epoll_fd    *epfd = (struct epoll_fd*)get_fd_internal(fd);
    
    if (epoll_ctl(epoll_id, EPOLL_CTL_DEL, fd, &ev) < 0)
        abort();
        
    if (epfd - epoll_fds != numfds - 1)
    {
        *epfd = epoll_fds[numfds-1];
        set_fd_internal(epfd->fd, (void*)epfd);
        
        /* update the epoll internal pointer as well */
        ev.events = epfd->events;
        ev.data.ptr = epfd;
        if (epoll_ctl(epoll_id, EPOLL_CTL_MOD, epfd->fd, &ev) < 0)
            abort();
    }
    
    --numfds;
}

void engine_change_fd_state(int fd, unsigned int stateplus)
{
    struct epoll_event ev;
    struct epoll_fd *epfd = (struct epoll_fd*)get_fd_internal(fd);
    
    ev.events = 0;
    ev.data.ptr = epfd;
    if (stateplus & FDF_WANTWRITE) ev.events |= EPOLLOUT;
    if (stateplus & FDF_WANTREAD) ev.events |= EPOLLIN|EPOLLHUP|EPOLLERR;
    
    if (ev.events != epfd->events)
    {
        epfd->events = ev.events;
        if (epoll_ctl(epoll_id, EPOLL_CTL_MOD, fd, &ev) < 0)
            abort();
    }
}

#define ENGINE_MAX_EVENTS 512
#define ENGINE_MAX_LOOPS (2 * (MAXCONNECTIONS / 512))

int engine_read_message(time_t delay)
{
    struct epoll_event events[ENGINE_MAX_EVENTS], *pevent;
    struct epoll_fd* epfd;
    int nfds, i, numloops = 0, eventsfull;
    unsigned int fdflags;
    int          fdtype;
    void         *fdvalue;
    aClient      *cptr;
    aListener    *lptr;
    
    do
    {
        nfds = epoll_wait(epoll_id, events, ENGINE_MAX_EVENTS, delay * 1000);
        
        if (nfds == -1)
        {
            if (errno == EINTR || errno == EAGAIN)
                return -1;
                
            report_error("epoll_wait: %s:%s", &me);
            sleep(5);
            return -1;
        }
        eventsfull = nfds == ENGINE_MAX_EVENTS;
        
        if (delay || numloops)
            NOW = timeofday = time(NULL);
        numloops++;
        
        for (i = 0, pevent = events; i < nfds; i++, pevent++)
        {
            epfd = pevent->data.ptr;
            if (epfd->fd != -1)
            {
                int rr = (epfd->events & pevent->events) & (EPOLLIN|EPOLLHUP|EPOLLERR);
                int rw = (epfd->events & pevent->events) & EPOLLOUT;
                
                get_fd_info(epfd->fd, &fdtype, &fdflags, &fdvalue);
                
                switch (fdtype)
                {
                case FDT_NONE:
                    break;
                    
                case FDT_AUTH:
                    cptr = (aClient*)fdvalue;
                    if (rr) read_authports(cptr);
                    if (rw && cptr->authfd >= 0) send_authports(cptr);  
                    check_client_fd(cptr);
                    break;
                    
                case FDT_LISTENER:
                    lptr = (aListener*)fdvalue;
                    if (rr) accept_connection(lptr);
                    break;
                    
                case FDT_RESOLVER:
                    do_dns_async();
                    break;
                    
                case FDT_CLIENT:
                    cptr = (aClient*)fdvalue;
                    readwrite_client(cptr, rr, rw);
                    break;
                    
                case FDT_CALLBACKP:
                    {
                        struct fd_callbackp *fdcb = (struct fd_callbackp*)fdvalue;
                        
                        fdcb->rdf = rr;
                        fdcb->wrf = rw;
                        (*fdcb->callback)(fdcb);
                        break;
                    }
                    
                default:
                    abort();
                }
            }
        }
    } while (eventsfull && numloops < ENGINE_MAX_LOOPS);
    
    return 0;
}

