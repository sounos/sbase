#include "evselect.h"
#include <errno.h>
#ifdef HAVE_EVSELECT
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/resource.h>
#include "mutex.h"
/* Initialize evselect  */
int evselect_init(EVBASE *evbase)
{
    //struct rlimit rlim;
    int max_fd = EV_MAX_FD;
    if(evbase)
    {
        evbase->ev_read_fds = calloc(1, sizeof(fd_set));			
        FD_ZERO((fd_set *)evbase->ev_read_fds);
        //FD_SET(0, (fd_set *)evbase->ev_read_fds);
        evbase->ev_write_fds = calloc(1, sizeof(fd_set));	
        FD_ZERO((fd_set *)evbase->ev_write_fds);
        //FD_SET(0, (fd_set *)evbase->ev_write_fds);	
        /*
        if(getrlimit(RLIMIT_NOFILE, &rlim) == 0
                && rlim.rlim_cur != RLIM_INFINITY )
        {
            max_fd = rlim.rlim_cur;		
        }
        evbase->evlist = (EVENT **)calloc(max_fd, sizeof(EVENT *));	
        */
        evbase->allowed = max_fd;
        return 0;
    }
    return -1;
}
/* Add new event to evbase */
int evselect_add(EVBASE *evbase, EVENT *event)
{
    int ev_flags = 0;
    if(evbase && event && event->ev_fd >= 0 && event->ev_fd < evbase->allowed)
    {
        MUTEX_LOCK(evbase->mutex);
        UPDATE_EVENT_FD(evbase, event);
        event->ev_base = evbase;
        if(evbase->ev_read_fds && (event->ev_flags & E_READ))
        {
            FD_SET(event->ev_fd, (fd_set *)evbase->ev_read_fds);
            ev_flags |= E_READ;
        }
        if(evbase->ev_read_fds && (event->ev_flags & E_WRITE))
        {
            ev_flags |= E_WRITE;
            FD_SET(event->ev_fd, (fd_set *)evbase->ev_write_fds);	
        }
        MUTEX_UNLOCK(evbase->mutex);
        return 0;
    }	
    return -1;
}

/* Update event in evbase */
int evselect_update(EVBASE *evbase, EVENT *event)
{
    int ev_flags = 0, add_ev_flags = 0, del_ev_flags = 0;
    if(evbase && event && event->ev_fd >= 0 && event->ev_fd < evbase->allowed)
    {
        MUTEX_LOCK(evbase->mutex);
        UPDATE_EVENT_FD(evbase, event);
        ev_flags = (event->ev_flags ^ event->old_ev_flags);
        add_ev_flags = (event->ev_flags & ev_flags);
        del_ev_flags = (event->old_ev_flags & ev_flags);

        if(add_ev_flags & E_READ)
        {
            FD_SET(event->ev_fd, (fd_set *)evbase->ev_read_fds);
            ev_flags |= E_READ;
        }
        if(del_ev_flags & E_READ)
        {
            FD_CLR(event->ev_fd, (fd_set *)evbase->ev_read_fds);
        }
        if(add_ev_flags & E_WRITE)
        {
            FD_SET(event->ev_fd, (fd_set *)evbase->ev_write_fds);
            ev_flags |= E_WRITE;
        }
        if(del_ev_flags & E_WRITE)
        {
            FD_CLR(event->ev_fd, (fd_set *)evbase->ev_write_fds);
        }
        MUTEX_UNLOCK(evbase->mutex);
        return 0;
    }
    return -1;
}
/* Delete event from evbase */
int evselect_del(EVBASE *evbase, EVENT *event)
{
    if(evbase && event && event->ev_fd >= 0 && event->ev_fd < evbase->allowed)
    {
        MUTEX_LOCK(evbase->mutex);
        if(evbase->ev_read_fds)
        {
            FD_CLR(event->ev_fd, (fd_set *)evbase->ev_read_fds);
        }
        if(evbase->ev_write_fds)
        {
            FD_CLR(event->ev_fd, (fd_set *)evbase->ev_write_fds);
        }
        REMOVE_EVENT_FD(evbase, event);
        MUTEX_UNLOCK(evbase->mutex);
        return 0;
    }
    return -1;
}

/* Loop evbase */
int evselect_loop(EVBASE *evbase, int loop_flag, struct timeval *tv)
{
    int i = 0, n = 0;
    int ev_flags = 0;
    fd_set rd_fd_set, wr_fd_set ;
    EVENT *ev = NULL;
    struct timeval timeout = {0};

    //if(evbase  && evbase->nfd > 0)
    if(evbase)
    {
        FD_ZERO(&rd_fd_set);
        memcpy(&rd_fd_set, evbase->ev_read_fds, sizeof(fd_set));
        FD_ZERO(&wr_fd_set);
        memcpy(&wr_fd_set, evbase->ev_write_fds, sizeof(fd_set));
        if(tv == NULL)
        {
            timeout.tv_sec = 0;
            timeout.tv_usec = 1000;
            tv = &timeout;
        }
        n = select(evbase->maxfd+1, &rd_fd_set, &wr_fd_set, NULL, tv);
        if(n <= 0) return n;
        for(i = 0; i <= evbase->maxfd; ++i)
        {
            if((ev = evbase->evlist[i]))
            {
                ev_flags = 0;
                if(FD_ISSET(i, &rd_fd_set))	
                {
                    ev_flags |= E_READ;
                }
                if(FD_ISSET(i, &wr_fd_set))
                {
                    ev_flags |= E_WRITE;
                }
                if(ev_flags == 0) continue;
                if((ev_flags  &= ev->ev_flags))	
                {
                    event_active(ev, ev_flags);
                }
            }			
        }
    }
    return n;
}

/* Reset evbase */
void evselect_reset(EVBASE *evbase)
{
    if(evbase)
    {
        evbase->maxfd = 0;
        FD_ZERO((fd_set *)evbase->ev_read_fds);
        FD_ZERO((fd_set *)evbase->ev_write_fds);
    }
    return ;
}

/* Clean evbase */
void evselect_clean(EVBASE *evbase)
{
    if(evbase)
    {
        MUTEX_DESTROY(evbase->mutex);
        //if(evbase->evlist)free(evbase->evlist);
        if(evbase->evs)free(evbase->evs);
        if(evbase->ev_fds)free(evbase->ev_fds);
        if(evbase->ev_read_fds)free(evbase->ev_read_fds);
        if(evbase->ev_write_fds)free(evbase->ev_write_fds);
        free(evbase);
    }
    return ;
}
#endif
