************************************************************************
*   IRC - Internet Relay Chat, src/socketengine_devpoll.c
*   Copyright (C) 2004 David Parton
*
* engine functions for the /dev/poll socket engine
*
*/

/* $Id$ */


#include "struct.h"
#include "common.h"
#include "sys.h"
#include "h.h"
#include "fds.h"

#include <unistd.h>
#include <fcntl.h>
#include <sys/devpoll.h>
#include <sys/poll.h>

static int devpoll_id = -1, numfds = 0;

void engine_init()
{
    devpoll_id = open("/dev/poll", O_RDWR);
}

void engine_add_fd(int fd)
{
    struct pollfd dev_fd;

    if (numfds >= MAXCONNECTIONS)
        abort();

    dev_fd.events = 0;
    dev_fd.revents = 0;
    dev_fd.fd = fd;
    if (write(devpoll_id, &dev_fd, sizeof(struct pollfd)) != sizeof(struct pollfd))
        abort();

    set_fd_internal(fd, 0);
    ++numfds;
}

void engine_del_fd(int fd)
{
    struct pollfd dev_fd;

    dev_fd.events = POLLREMOVE;
    dev_fd.revents = 0;
    dev_fd.fd = fd;
    if (write(devpoll_id, &dev_fd, sizeof(struct pollfd)) != sizeof(struct pollfd))
        abort();

    --numfds;
}

void engine_change_fd_state(int fd, unsigned int stateplus)
{
    unsigned int events = 0;
    struct pollfd dev_fd;

    if (stateplus & FDF_WANTWRITE) events |= POLLOUT;
    if (stateplus & FDF_WANTREAD) events |= POLLIN|POLLHUP|POLLERR;

    dev_fd.events = events;
    dev_fd.revents = 0;
    dev_fd.fd = fd;

    if (write(devpoll_id, &dev_fd, sizeof(struct pollfd)) != sizeof(struct pollfd))
        abort();

    set_fd_internal(fd, (void*)events);
}

#define ENGINE_MAX_EVENTS 512
#define ENGINE_MAX_LOOPS (2 * (MAXCONNECTIONS / 512))

int engine_read_message(time_t delay)
{
    struct pollfd events[ENGINE_MAX_EVENTS], *pevent;
    struct dvpoll dopoll;
    int nfds, i, numloops = 0, eventsfull;
    unsigned int fdflags, fdevents;
    int          fdtype;
    void         *fdvalue;
    aClient      *cptr;   
    aListener    *lptr;

    dopoll.dp_fds = events;
    dopoll.dp_nfds = ENGINE_MAX_EVENTS;
    dopoll.dp_timeout = delay;
    do
    {
        nfds = ioctl(devpoll_id, DP_POLL, &dopoll);

        if (nfds < 0)
        {
            if (errno == EINTR || errno == EAGAIN)
                return -1; 

            report_error("ioctl(devpoll): %s:%s", &me);
            sleep(5);
            return -1;
        }
        eventsfull = nfds == ENGINE_MAX_EVENTS;

        if (delay || numloops) 
            NOW = timeofday = time(NULL);
        numloops++;

        for (i = 0, pevent = events; i < nfds; i++, pevent++)
        {
            fdevents = (unsigned int)get_fd_internal(pevent->fd);
            if (pevent->fd != -1)
            {
                int rr = (pevent->revents & (POLLIN|POLLHUP|POLLERR)) && (fdevents & (POLLIN|POLLHUP|POLLERR));
                int rw = (pevent->revents & POLLOUT) && (fdevents & POLLOUT);

                get_fd_info(pevent->fd, &fdtype, &fdflags, &fdvalue);

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