#ifndef _EVTIMER_H
#define _EVTIMER_H
#include "mutex.h"
typedef void (EVTCALLBACK)(void *);
typedef struct _EVTNODE
{
    int id;
    int ison;
    off_t evusec;
    void *arg;
    EVTCALLBACK *handler;
    struct _EVTNODE *prev;
    struct _EVTNODE *next;
}EVTNODE;
#define  EVTNODE_MAX        65536
typedef struct _EVTIMER
{
   int current;
   int ntimeout;
   MUTEX *mutex;
   EVTNODE nodes[EVTNODE_MAX];
   unsigned short timeouts[EVTNODE_MAX];
   EVTNODE *left;
   EVTNODE *head;
   EVTNODE *tail;
}EVTIMER;

/* initialize evtimer */
EVTIMER *evtimer_init();
/* add event timer */
int evtimer_add(EVTIMER *evtimer, off_t timeout, EVTCALLBACK *handler, void *arg);
/* update event timer */
int evtimer_update(EVTIMER *evtimer, int evid, off_t timeout, EVTCALLBACK *handler, void *arg);
/* delete event timer */
int evtimer_delete(EVTIMER *evtimer, int evid);
/* check timeout */
void evtimer_check(EVTIMER *evtimer);
/* reset evtimer */
void evtimer_reset(EVTIMER *evtimer);
/* clean evtimer */
void evtimer_clean(EVTIMER *evtimer);
#define PEVTIMER(ptr) ((EVTIMER *)ptr)
#define EVTIMER_INIT() evtimer_init()
#define EVTIMER_ADD(ptr, timeout, evhandler, evarg) \
    evtimer_add(PEVTIMER(ptr), (off_t)timeout, evhandler, evarg)
#define EVTIMER_UPDATE(ptr, evid, timeout, evhandler, evarg) \
    evtimer_update(PEVTIMER(ptr), evid, (off_t)timeout, evhandler, evarg)
#define EVTIMER_DEL(ptr, evid) evtimer_delete(PEVTIMER(ptr), evid)
#define EVTIMER_CHECK(ptr) evtimer_check(PEVTIMER(ptr))
#define EVTIMER_RESET(ptr) evtimer_reset(PEVTIMER(ptr))
#define EVTIMER_CLEAN(ptr) evtimer_clean(PEVTIMER(ptr))
#endif
