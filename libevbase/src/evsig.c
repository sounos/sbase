#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include "evbase.h"
#ifdef HAVE_EVPOLL
#include <poll.h>
#endif
#ifdef HAVE_EVEPOLL
#include <sys/epoll.h>
#endif
#ifdef HAVE_EVKQUEUE
#include <sys/event.h>
#endif
#ifdef HAVE_EVKQUEUE
void evsig_kqueue_init(EVSIG *evsig)
{
    struct kevent kev = {0};
    int n = 0;

    if(evsig && evsig->fd > 0)
    {
        if((evsig->efd = kqueue()) > 0)
        {
            EV_SET(&kev, evsig->fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
            n = kevent(evsig->efd, &kev, 1, NULL, 0, NULL);
        }
    }
    return ;
}

void evsig_kqueue_wait(EVSIG *evsig)
{
    struct kevent kev = {0};
    int n = 0;

    if(evsig && evsig->efd > 0 && evsig->fd > 0)
    {
        evsig->flag = 0;
        n = kevent(evsig->efd, NULL, 0, &kev, 1, NULL);
        evsig->flag = 0;
        EV_SET(&kev, evsig->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        n = kevent(evsig->efd, &kev, 1, NULL, 0, NULL);
    }
    return ;
}
void evsig_kqueue_wakeup(EVSIG *evsig)
{
    struct kevent kev = {0};
    int n = 0;

    if(evsig && evsig->efd > 0 && evsig->fd > 0)
    {
        EV_SET(&kev, evsig->fd, EVFILT_WRITE, EV_ADD, 0, 0, NULL);
        n = kevent(evsig->efd, &kev, 1, NULL, 0, NULL);
    }
    return ;
}
void evsig_kqueue_close(EVSIG *evsig)
{
    struct kevent kev = {0};
    int n = 0;

    if(evsig && evsig->efd > 0 && evsig->fd > 0)
    {
        EV_SET(&kev, evsig->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        n = kevent(evsig->efd, &kev, 1, NULL, 0, NULL);
        EV_SET(&kev, evsig->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        n = kevent(evsig->efd, &kev, 1, NULL, 0, NULL);
        close(evsig->efd);
        evsig->efd = 0;
    }
    return ;
}
#endif
#ifdef HAVE_EVEPOLL
void evsig_epoll_init(EVSIG *evsig)
{
    struct epoll_event ev;
    int n = 0;

    if(evsig && evsig->fd > 0)
    {
        if((evsig->efd  = epoll_create(1)) > 0)
        {
            memset(&ev, 0, sizeof(struct epoll_event));
            ev.data.fd = evsig->fd;
            ev.events = EPOLLIN;
            ev.data.ptr = (void *)evsig;
            n = epoll_ctl(evsig->efd, EPOLL_CTL_ADD, evsig->fd, &ev);
        }
    }
    return ;
}
void evsig_epoll_wait(EVSIG *evsig)
{
    struct epoll_event ev;
    int n = 0;

    if(evsig && evsig->efd > 0 && evsig->fd > 0)
    {
        evsig->flag = 0;
        n = epoll_wait(evsig->efd, &ev, 1, -1);
        evsig->flag = 0;
        memset(&ev, 0, sizeof(struct epoll_event));
        ev.data.fd = evsig->fd;
        ev.events = EPOLLIN;
        ev.data.ptr = (void *)evsig;
        n = epoll_ctl(evsig->efd, EPOLL_CTL_MOD, evsig->fd, &ev);
    }
    return ;
}
void evsig_epoll_wakeup(EVSIG *evsig)
{
    struct epoll_event ev;
    int n = 0;

    if(evsig && evsig->efd > 0 && evsig->fd > 0)
    {
        memset(&ev, 0, sizeof(struct epoll_event));
        ev.data.fd = evsig->fd;
        ev.events = EPOLLIN|EPOLLOUT;
        ev.data.ptr = (void *)evsig;
        n = epoll_ctl(evsig->efd, EPOLL_CTL_MOD, evsig->fd, &ev);
    }
    return ;
}

void evsig_epoll_close(EVSIG *evsig)
{
    struct epoll_event ev;
    int n = 0;

    if(evsig && evsig->efd > 0 && evsig->fd > 0)
    {
        memset(&ev, 0, sizeof(struct epoll_event));
        ev.data.fd = evsig->fd;
        ev.events = 0;
        ev.data.ptr = (void *)evsig;
        n = epoll_ctl(evsig->efd, EPOLL_CTL_DEL, evsig->fd, &ev);
        close(evsig->fd);
        evsig->fd = 0;
    }
    return ;
}
#endif

/* evsig */
void evsig_set(EVSIG *evsig, int fd)
{
	if(evsig)
	{
        memset(evsig, 0, sizeof(EVSIG));
		if(fd > 0)
		{
			evsig->fd		= 	fd;
#ifdef HAVE_EVEPOLL
        return evsig_epoll_init(evsig);
#endif
#ifdef HAVE_EVKQUEUE
        return evsig_kqueue_init(evsig);
#endif
		}		
	}
    return ;
}

/* wait event */
void evsig_wait(EVSIG *evsig)
{
    if(evsig)
    {
#ifdef HAVE_EVEPOLL
        return evsig_epoll_wait(evsig);
#endif
#ifdef HAVE_EVKQUEUE
        return evsig_kqueue_wait(evsig);
#endif
    }
    return ;
}

/* wakeup */
void evsig_wakeup(EVSIG *evsig)
{
    if(evsig)
    {
        if(evsig->flag == 0)
        {
            evsig->flag = 1;
#ifdef HAVE_EVEPOLL
            return evsig_epoll_wakeup(evsig);
#endif
#ifdef HAVE_EVKQUEUE
            return evsig_kqueue_wakeup(evsig);
#endif
        }
    }
    return ;
}

/* close */
void evsig_close(EVSIG *evsig)
{
    if(evsig)
    {
#ifdef HAVE_EVEPOLL
        return evsig_epoll_close(evsig);
#endif
#ifdef HAVE_EVKQUEUE
        return evsig_kqueue_close(evsig);
#endif
    }
    return ;
}

