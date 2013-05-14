#include "evbase.h"
#ifdef HAVE_EVEPOLL
#ifndef _EVEPOLL_H
#define _EVEPOLL_H
/* Initialize evepoll  */
int evepoll_init(EVBASE *evbase);
/* Add new event to evbase */
int evepoll_add(EVBASE *evbase, EVENT *event);
/* Update event in evbase */
int evepoll_update(EVBASE *evbase, EVENT *event);
/* Delete event from evbase */
int evepoll_del(EVBASE *evbase, EVENT *event);
/* Loop evbase */
int evepoll_loop(EVBASE *evbase, int, struct timeval *tv);
/* Reset evbase */
void evepoll_reset(EVBASE *evbase);
/* Clean evbase */
void evepoll_clean(EVBASE *evbase);
#endif
#endif

