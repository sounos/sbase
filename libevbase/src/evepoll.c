#include "evepoll.h"
#include <errno.h>
#ifdef HAVE_EVEPOLL
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <fcntl.h>
#include "logger.h"
//#include "log.h"
#include "mutex.h"
/* Initialize evepoll  */
int evepoll_init(EVBASE *evbase)
{
    //struct rlimit rlim;
    int max_fd = EV_MAX_FD;
    if(evbase)
    {
        /*
        if(getrlimit(RLIMIT_NOFILE, &rlim) == 0
                && rlim.rlim_cur != RLIM_INFINITY )
        {
            max_fd = rlim.rlim_cur;
        }
        evbase->evlist  = (EVENT **)calloc(max_fd, sizeof(EVENT *));
        */
        evbase->efd 	= epoll_create(max_fd);
        fcntl(evbase->efd, F_SETFD, FD_CLOEXEC);
        evbase->evs 	= calloc(max_fd, sizeof(struct epoll_event));
        evbase->allowed = max_fd;
        return 0;
    }
    return -1;
}
/* Add new event to evbase */
int evepoll_add(EVBASE *evbase, EVENT *event)
{
    int op = 0, ev_flags = 0, add = 0, ret = 0;
    struct epoll_event ep_event = {0, {0}};

    if(evbase && event && event->ev_fd >= 0  && event->ev_fd < evbase->allowed)
    {
        MUTEX_LOCK(evbase->mutex);
        event->ev_base = evbase;
        if(event->ev_flags & E_READ)
        {
            ev_flags |= EPOLLIN;
            add = 1;
        }	
        if(event->ev_flags & E_WRITE)
        {
            ev_flags |= EPOLLOUT;
            add = 1;
        }
        if(event->ev_flags & E_EPOLL_ET)
        {
            ev_flags |= EPOLLET;
        }
        //ev_flags |= EPOLLERR | EPOLLHUP;
        if(add)
        {
            UPDATE_EVENT_FD(evbase, event);
            op = EPOLL_CTL_ADD; 
            memset(&ep_event, 0, sizeof(struct epoll_event));
            ep_event.data.fd = event->ev_fd;
            ep_event.events = ev_flags;
            ep_event.data.ptr = (void *)event;
            if(epoll_ctl(evbase->efd, op, event->ev_fd, &ep_event) < 0)
            {
                if(errno == ENOENT)
                    epoll_ctl(evbase->efd, EPOLL_CTL_ADD, event->ev_fd, &ep_event);
                else if(errno == EEXIST)
                    epoll_ctl(evbase->efd, EPOLL_CTL_MOD, event->ev_fd, &ep_event);
                else
                {
                    ret = -1;
                }
            }
        }
        MUTEX_UNLOCK(evbase->mutex);
    }
    return ret;
}

/* Update event in evbase */
int evepoll_update(EVBASE *evbase, EVENT *event)
{
    struct epoll_event ep_event = {0, {0}};
    int op = 0, ev_flags = 0, ret = -1;

    if(evbase && event && event->ev_fd >= 0 && event->ev_fd < evbase->allowed)
    {
        MUTEX_LOCK(evbase->mutex);
        UPDATE_EVENT_FD(evbase, event);
        if(event->ev_flags & E_READ)
        {
            ev_flags |= EPOLLIN;
        }
        if(event->ev_flags & E_WRITE)
        {
            ev_flags |= EPOLLOUT;
        }
        if(event->ev_flags & E_EPOLL_ET)
        {
            ev_flags |= EPOLLET;
        }
        //ev_flags |= EPOLLERR | EPOLLHUP;
        op = EPOLL_CTL_MOD;
        if(evbase->evlist[event->ev_fd] == NULL) op = EPOLL_CTL_ADD;
        memset(&ep_event, 0, sizeof(struct epoll_event));
        ep_event.data.fd = event->ev_fd;
        ep_event.events = ev_flags;
        ep_event.data.ptr = (void *)event;
        if(epoll_ctl(evbase->efd, op, event->ev_fd, &ep_event) < 0)
        {
            if(errno == ENOENT)
            {
                epoll_ctl(evbase->efd, EPOLL_CTL_ADD, event->ev_fd, &ep_event);
            }
            else if(errno == EEXIST)
                epoll_ctl(evbase->efd, EPOLL_CTL_MOD, event->ev_fd, &ep_event);
            else
            {
                ret = -1;
            }
        }
        MUTEX_UNLOCK(evbase->mutex);
    }
    return ret;	
}

/* Delete event from evbase */
int evepoll_del(EVBASE *evbase, EVENT *event)
{
    struct epoll_event ep_event;

    if(evbase && event && event->ev_fd >= 0 && event->ev_fd < evbase->allowed)
    {
        MUTEX_LOCK(evbase->mutex);
        if(evbase->evlist[event->ev_fd]) 
        {
            ep_event.data.fd = event->ev_fd;
            ep_event.data.ptr = event;
            epoll_ctl(evbase->efd, EPOLL_CTL_DEL, event->ev_fd, &ep_event);
            REMOVE_EVENT_FD(evbase, event);
        }
        MUTEX_UNLOCK(evbase->mutex);
    }
    return -1;
}

/* Loop evbase */
int evepoll_loop(EVBASE *evbase, int loop_flags, struct timeval *tv)
{
    int i = 0, n = 0, timeout = -1, flags = 0, ev_flags = 0, fd = 0, event = 0;
    struct epoll_event *evp = NULL;
    EVENT *ev = NULL;

    if(evbase)
    {
        if(tv) 
        {
            timeout = tv->tv_sec * 1000 + (tv->tv_usec + 999) / 1000;
            
        }
        //memset(evbase->evs, 0, sizeof(struct epoll_event) * evbase->allowed);
        n = epoll_wait(evbase->efd, (struct epoll_event *)(evbase->evs), evbase->allowed, timeout);
        //n = epoll_wait(evbase->efd, (struct epoll_event *)evbase->evs, evbase->maxfd+1, timeout);
        if(n <= 0)
        {
            if(n < 0){fprintf(stderr, "epoll_wait(%d, %p, %d, %d) failed, %s\n", evbase->efd, evbase->evs, evbase->maxfd, timeout, strerror(errno));}
            return n;
        }
        //WARN_LOG("loop()=> %d", n);
        for(i = 0; i < n; i++)
        {
            evp = &(((struct epoll_event *)evbase->evs)[i]);
            ev = (EVENT *)evp->data.ptr;
            if(ev == NULL) continue;
            fd = ev->ev_fd;
            flags = evp->events;
            //fd = evp->data.fd;
            if(fd >= 0 && fd < evbase->allowed && evbase->evlist[fd] && ev == evbase->evlist[fd])
            {
                ev_flags = 0;
                if(flags & (EPOLLHUP|EPOLLERR))
                {
                    ev_flags = E_READ|E_WRITE;
                }
                else
                {
                    if(flags & EPOLLIN) ev_flags |= E_READ;
                    if(flags & EPOLLOUT) ev_flags |= E_WRITE;
                }
                //event = (ev_flags & ev->ev_flags);
                //if((ev_flags &= ev->ev_flags))
                if(ev_flags)
                {
                    event_active(ev, ev_flags);
                }
                else
                {
                    WARN_LOGGER(evbase->logger, "ev:%p fd:%d evflags:%d event:%d", ev, fd, ev->ev_flags, ev_flags); 
                    //evepoll_update(evbase, ev);  
                }
            }
        }
        //WARN_LOG("over_loop()=> %d", n);
    }
    return n;
}

/* Reset evbase */
void evepoll_reset(EVBASE *evbase)
{
    if(evbase)
    {
        if(evbase->efd > 0)close(evbase->efd);
        evbase->efd = epoll_create(evbase->allowed);
        fcntl(evbase->efd, F_SETFD, FD_CLOEXEC);
        evbase->maxfd = 0;
        if(evbase->evs)memset(evbase->evs, 0, evbase->allowed * sizeof(struct epoll_event));
        if(evbase->evlist)memset(evbase->evlist, 0, evbase->allowed * sizeof(EVENT *));
    }
    return ;
}

/* Clean evbase */
void evepoll_clean(EVBASE *evbase)
{
    if(evbase)
    {
        //if(evbase->evlist)free(evbase->evlist);
        if(evbase->evs)free(evbase->evs);
        if(evbase->ev_fds)free(evbase->ev_fds);
        if(evbase->ev_read_fds)free(evbase->ev_read_fds);
        if(evbase->ev_write_fds)free(evbase->ev_write_fds);
        if(evbase->efd > 0 )close(evbase->efd);
        MUTEX_DESTROY(evbase->mutex);
        free(evbase);
    }	
    return ;
}
#endif
