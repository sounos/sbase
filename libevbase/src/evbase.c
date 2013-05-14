#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <errno.h>
#include "evbase.h"
#ifdef HAVE_EVPORT
#include "evport.h"
#endif
#ifdef HAVE_EVSELECT
#include "evselect.h"
#endif
#ifdef HAVE_EVPOLL
#include "evpoll.h"
#endif
#ifdef HAVE_EVRTSIG
#include "evrtsig.h"
#endif
#ifdef HAVE_EVEPOLL
#include "evepoll.h"
#endif
#ifdef HAVE_EVKQUEUE
#include "evkqueue.h"
#endif
#ifdef HAVE_EVDEVPOLL
#include "evdevpoll.h"
#endif
#ifdef WIN32
#include "evwin32.h"
#endif
#include "mutex.h"
#include "logger.h"
typedef struct _EVOPS
{
    char    *name ;
    int     (*init)(struct _EVBASE *);
    int     (*add)(struct _EVBASE *, struct _EVENT*);
    int     (*update)(struct _EVBASE *, struct _EVENT*);
    int     (*del)(struct _EVBASE *, struct _EVENT*);
    int     (*loop)(struct _EVBASE *, int , struct timeval *tv);
    void    (*reset)(struct _EVBASE *);
    void    (*clean)(struct _EVBASE *);
}EVOPS;
static EVOPS evops[EOP_LIMIT];
static int evops_default =      -1;
/* set event operating */
int evbase_set_evops(EVBASE *evbase, int evopid)
{
    if(evbase)
    {
        if(evopid >= 0 && evopid < EOP_LIMIT && evops[evopid].name != NULL)
        {
            if(evbase->reset)evbase->reset(evbase);
            if(evops[evopid].init) evbase->init = evops[evopid].init;
            if(evops[evopid].add) evbase->add = evops[evopid].add;
            if(evops[evopid].update) evbase->update = evops[evopid].update;
            if(evops[evopid].del) evbase->del = evops[evopid].del;
            if(evops[evopid].loop) evbase->loop = evops[evopid].loop;
            if(evops[evopid].reset) evbase->reset = evops[evopid].reset;
            if(evops[evopid].clean) evbase->clean = evops[evopid].clean;
            if(evbase->init(evbase) == -1)
                evbase->set_evops(evbase, evops_default);
            evbase->evopid = evopid;
            return 0;
        }
    }
    return -1;
}

int evbase_set_logfile(EVBASE *evbase, char *logfile)
{
    if(evbase && logfile)
    {
        LOGGER_INIT(evbase->logger, logfile);
        return 0;
    }
    return -1;
}

/* Initialize evbase */
EVBASE *evbase_init(int use_lock)
{
    int evops_default_v = -1;
    EVBASE *evbase = NULL;

    if((evbase = (EVBASE *)calloc(1, sizeof(EVBASE))))
    {
        if(use_lock){MUTEX_INIT(evbase->mutex);}
#ifdef HAVE_EVPORT
        evops_default_v = EOP_PORT;
        evops[EOP_PORT].name = "PORT";
        evops[EOP_PORT].init      = &evport_init;
        evops[EOP_PORT].add       = &evport_add;
        evops[EOP_PORT].update    = &evport_update;
        evops[EOP_PORT].del       = &evport_del;
        evops[EOP_PORT].loop      = &evport_loop;
        evops[EOP_PORT].reset     = &evport_reset;
        evops[EOP_PORT].clean     = &evport_clean;
#endif
#ifdef HAVE_EVSELECT
        evops_default_v = EOP_SELECT;
        evops[EOP_SELECT].name    = "SELECT";
        evops[EOP_SELECT].init    = &evselect_init;
        evops[EOP_SELECT].add     = &evselect_add;
        evops[EOP_SELECT].update  = &evselect_update;
        evops[EOP_SELECT].del     = &evselect_del;
        evops[EOP_SELECT].loop    = &evselect_loop;
        evops[EOP_SELECT].reset   = &evselect_reset;
        evops[EOP_SELECT].clean   = &evselect_clean;
#endif
#ifdef HAVE_EVPOLL
        evops_default_v = EOP_POLL;
        evops[EOP_POLL].name      = "POLL";
        evops[EOP_POLL].init      = &evpoll_init;
        evops[EOP_POLL].add       = &evpoll_add;
        evops[EOP_POLL].update    = &evpoll_update;
        evops[EOP_POLL].del       = &evpoll_del;
        evops[EOP_POLL].loop      = &evpoll_loop;
        evops[EOP_POLL].reset     = &evpoll_reset;
        evops[EOP_POLL].clean     = &evpoll_clean;
#endif
#ifdef HAVE_EVRTSIG
        evops_default_v = EOP_RTSIG;
        evops[EOP_RTSIG].name     = "RTSIG" ;
        evops[EOP_RTSIG].init     = &evrtsig_init;
        evops[EOP_RTSIG].add      = &evrtsig_add;
        evops[EOP_RTSIG].update   = &evrtsig_update;
        evops[EOP_RTSIG].del      = &evrtsig_del;
        evops[EOP_RTSIG].loop     = &evrtsig_loop;
        evops[EOP_RTSIG].reset    = &evrtsig_reset;
        evops[EOP_RTSIG].clean    = &evrtsig_clean;
#endif
#ifdef HAVE_EVEPOLL
        evops_default_v = EOP_EPOLL;
        evops[EOP_EPOLL].name     = "EPOLL";
        evops[EOP_EPOLL].init     = &evepoll_init;
        evops[EOP_EPOLL].add      = &evepoll_add;
        evops[EOP_EPOLL].update   = &evepoll_update;
        evops[EOP_EPOLL].del      = &evepoll_del;
        evops[EOP_EPOLL].loop     = &evepoll_loop;
        evops[EOP_EPOLL].reset    = &evepoll_reset;
        evops[EOP_EPOLL].clean    = &evepoll_clean;
#endif
#ifdef HAVE_EVKQUEUE
        evops_default_v = EOP_KQUEUE;
        evops[EOP_KQUEUE].name    = "KQUEUE";
        evops[EOP_KQUEUE].init    = &evkqueue_init;
        evops[EOP_KQUEUE].add     = &evkqueue_add;
        evops[EOP_KQUEUE].update  = &evkqueue_update;
        evops[EOP_KQUEUE].del     = &evkqueue_del;
        evops[EOP_KQUEUE].loop    = &evkqueue_loop;
        evops[EOP_KQUEUE].reset   = &evkqueue_reset;
        evops[EOP_KQUEUE].clean   = &evkqueue_clean;
#endif
#ifdef HAVE_EVDEVPOLL
        evops_default_v = EOP_DEVPOLL;
        evops[EOP_DEVPOLL].name   = "/dev/poll";
        evops[EOP_DEVPOLL].init   = &evdevpoll_init;
        evops[EOP_DEVPOLL].add    = &evdevpoll_add;
        evops[EOP_DEVPOLL].update = &evdevpoll_update;
        evops[EOP_DEVPOLL].del    = &evdevpoll_del;
        evops[EOP_DEVPOLL].loop   = &evdevpoll_loop;
        evops[EOP_DEVPOLL].reset  = &evdevpoll_reset;
        evops[EOP_DEVPOLL].clean  = &evdevpoll_clean;
#endif
#ifdef WIN32
        evops_default_v = EOP_WIN32;
        evops[EOP_WIN32].name     = "WIN32";
        evops[EOP_WIN32].init     = &evwin32_init;
        evops[EOP_WIN32].add      = &evwin32_add;
        evops[EOP_WIN32].update   = &evwin32_update;
        evops[EOP_WIN32].del      = &evwin32_del;
        evops[EOP_WIN32].loop     = &evwin32_loop;
        evops[EOP_WIN32].reset    = &evwin32_reset;
        evops[EOP_WIN32].clean    = &evwin32_clean;
#endif
        evbase->set_evops   = evbase_set_evops;
        //evbase->clean 	=  evbase_clean;
        evops_default = evops_default_v;
        if(evops_default_v == -1 || evbase->set_evops(evbase, evops_default_v) == -1)
        {
            free(evbase); 
            fprintf(stderr, "Initialize evbase to default[%d] failed, %s\n", 
                    evops_default, strerror(errno));
            evbase = NULL;
        }
    }
    return evbase;
}

/* Set event */
void event_set(EVENT *event, int fd, int flags, void *arg, void *handler)
{
	if(event)
	{
		if(fd > 0 && handler)
		{
            if(flags & E_LOCK){MUTEX_INIT(event->mutex);}
			event->ev_fd		= 	fd;
			event->ev_flags		=	flags;
			event->ev_arg		=	arg;
			event->ev_handler	=	handler;
		}		
	}
    return ;
}

/* Add event flags */
void event_add(EVENT *event, int flags)
{
	if(event && event->ev_base)
	{
        MUTEX_LOCK(event->mutex);
        //if((flags & event->ev_flags) != flags)
        if(flags)
        {
            //WARN_LOGGER(event->ev_base->logger, "ev_fd:%d add_event:%d ev_flags:%d old_ev_flags:%d", event->ev_fd, flags, event->ev_flags, event->old_ev_flags);
            event->old_ev_flags = event->ev_flags;
            event->ev_flags |= flags;
            if(event->ev_base && event->ev_base->update)
            {
                event->ev_base->update(event->ev_base, event);
            }
            //WARN_LOGGER(event->ev_base->logger, "ev:%p ev_fd:%d add_event:%d ev_flags:%d old_ev_flags:%d", event, event->ev_fd, flags, event->ev_flags, event->old_ev_flags);
        }
        MUTEX_UNLOCK(event->mutex);
	}
    return ;
}

/* Delete event flags */
void event_del(EVENT *event, int flags)
{
	if(event && event->ev_base)
	{
        MUTEX_LOCK(event->mutex);
		//if((flags & event->ev_flags))
        if(flags)
		{
            //WARN_LOGGER(event->ev_base->logger, "ev_fd:%d del_event:%d ev_flags:%d old_ev_flags:%d", event->ev_fd, flags, event->ev_flags, event->old_ev_flags);
            event->old_ev_flags = event->ev_flags;
			event->ev_flags &= ~flags;
            if(event->ev_base && event->ev_base->update)
			{
                event->ev_base->update(event->ev_base, event);
			}
            //WARN_LOGGER(event->ev_base->logger, "ev:%p ev_fd:%d del_event:%d ev_flags:%d old_ev_flags:%d", event, event->ev_fd, flags, event->ev_flags, event->old_ev_flags);
		}
        MUTEX_UNLOCK(event->mutex);
	}	
    return ;
}

/* Destroy event */
void event_destroy(EVENT *event)
{
    if(event)
    {
        event->ev_flags = 0;
        if(event->ev_base && event->ev_base->del)
        {
            event->ev_base->del(event->ev_base, event);
            event->ev_base = NULL;
        }
    }
    return ;
}

/* Active event */
void event_active(EVENT *event, int ev_flags)
{
	int e_flags = ev_flags;
	if(event)
    {
        if(event->ev_handler && event->ev_base && event->ev_flags)
        {
            event->ev_handler(event->ev_fd, e_flags, event->ev_arg);	
        }
        if(!(event->ev_flags & E_PERSIST) && event->ev_base)
        {
        	event_destroy(event);
        }
    }
    return ;
}

/* Clean event */
void event_clean(EVENT *event)
{
	if(event)
	{
        MUTEX_DESTROY(event->mutex);
	}
    return ;
}
