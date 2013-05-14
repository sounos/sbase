#include "evbase.h"
#ifdef HAVE_EVPOLL
#ifndef _EVPOLL_H
#define _EVPOLL_H
/* Initialize evpoll  */
int evpoll_init(EVBASE *evbase);
/* Add new event to evbase */
int evpoll_add(EVBASE *evbase, EVENT *event);
/* Update event in evbase */
int evpoll_update(EVBASE *evbase, EVENT *event);
/* Delete event from evbase */
int evpoll_del(EVBASE *evbase, EVENT *event);
/* Loop evbase */
int evpoll_loop(EVBASE *evbase, int, struct timeval *tv);
/* Reset evbase */
void evpoll_reset(EVBASE *evbase);
/* Clean evbase */
void evpoll_clean(EVBASE *evbase);
#endif
#endif

