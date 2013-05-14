#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#ifndef _EVBASE_H
#define _EVBASE_H
#ifdef __cplusplus
extern "C" {
#endif
#define E_READ		0x01
#define E_WRITE		0x02
#define E_CLOSE		0x04
#define E_PERSIST	0x08
#define E_EPOLL_ET  0x10
#define E_LOCK      0x20
#define EV_MAX_FD	65000
/*event operating */
#define EOP_PORT        0x00
#define EOP_SELECT      0x01
#define EOP_POLL        0x02
#define EOP_RTSIG       0x03
#define EOP_EPOLL       0x04
#define EOP_KQUEUE      0x05
#define EOP_DEVPOLL     0x06
#define EOP_WIN32       0x07
#define EOP_LIMIT       8
struct _EVENT;
/*
#ifndef __TYPEDEF__MUTEX
#define __TYPEDEF__MUTEX
#ifdef HAVE_SEMAPHORE
#include <semaphore.h>
typedef struct _MUTEX
{
    sem_t mutex;
    sem_t cond;
}MUTEX;
#else
#include <pthread.h>
typedef struct _MUTEX
{
    pthread_mutex_t mutex;
    pthread_cond_t  cond;
    int nowait;
    int bits;
}MUTEX;
#endif
#endif
*/
#ifndef _TYPEDEF_EVBASE
#define _TYPEDEF_EVBASE
typedef struct _EVBASE
{
	int efd;
    int maxfd;
	int allowed;
    int evopid;

	void *ev_read_fds;
	void *ev_write_fds;
	void *ev_fds;
	void *evs;
    void *mutex;
    void *logger;
    struct _EVENT *evlist[EV_MAX_FD];

	int	    (*init)(struct _EVBASE *);
	int	    (*add)(struct _EVBASE *, struct _EVENT*);
	int 	(*update)(struct _EVBASE *, struct _EVENT*);
	int 	(*del)(struct _EVBASE *, struct _EVENT*);
	int	    (*loop)(struct _EVBASE *, int , struct timeval *tv);
	void	(*reset)(struct _EVBASE *);
	void 	(*clean)(struct _EVBASE *);
    int     (*set_evops)(struct _EVBASE *, int evopid);
}EVBASE;
EVBASE *evbase_init(int use_lock);
int evbase_set_logfile(EVBASE *evbase, char *logfile);
#define NEW_EVENT_FD(evbase, event)                                     \
do{                                                                     \
    if(event->ev_fd > evbase->maxfd) evbase->maxfd = event->ev_fd;      \
    evbase->evlist[event->ev_fd] = event;                               \
}while(0)
#define UPDATE_EVENT_FD(evbase, event)                                  \
do{                                                                     \
    evbase->evlist[event->ev_fd] = event;                               \
    if(event->ev_fd > evbase->maxfd) evbase->maxfd = event->ev_fd;      \
}while(0)
#define REMOVE_EVENT_FD(evbase, event)                                  \
do                                                                      \
{                                                                       \
    if(event->ev_fd == evbase->maxfd) evbase->maxfd = event->ev_fd -1;  \
    evbase->evlist[event->ev_fd] = NULL;                                \
}while(0)
#endif
#ifndef _TYPEDEF_EVENT
#define _TYPEDEF_EVENT
typedef struct _EVENT
{
	int ev_flags;
	int old_ev_flags;
    int ev_fd;
    int bits;

    void *mutex;
	struct _EVBASE *ev_base;
	void *ev_arg;
	void (*ev_handler)(int fd, int flags, void *arg);	
}EVENT;
/* Set event */
void event_set(EVENT *event, int fd, int flags, void *arg, void *handler);
/* Add event */
void event_add(EVENT *event, int flags);
/* Delete event */
void event_del(EVENT *event, int flags);
/* Active event */
void event_active(EVENT *event, int ev_flags);
/* Destroy event */
void event_destroy(EVENT *event);
/* Clean event */
void event_clean(EVENT *event);
#endif 
#ifndef __TYPEDEF_EVSIG__
#define __TYPEDEF_EVSIG__
typedef struct _EVSIG
{
    int efd;
    int fd;
    int flag;
    int bits;
}EVSIG;
void evsig_set(EVSIG *evsig, int fd);
void evsig_wait(EVSIG *evsig);
void evsig_wakeup(EVSIG *evsig);
void evsig_close(EVSIG *evsig);
#endif
#ifdef __cplusplus
 }
#endif

#endif
