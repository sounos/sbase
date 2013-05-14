#include "evbase.h"
#ifdef HAVE_EVKQUEUE
#ifndef _EVKQUEUE_H
#define _EVKQUEUE_H
/* Initialize evkqueue  */
int evkqueue_init(EVBASE *evbase);
/* Add new event to evbase */
int evkqueue_add(EVBASE *evbase, EVENT *event);
/* Update event in evbase */
int evkqueue_update(EVBASE *evbase, EVENT *event);
/* Delete event from evbase */
int evkqueue_del(EVBASE *evbase, EVENT *event);
/* Loop evbase */
int evkqueue_loop(EVBASE *evbase, int, struct timeval *tv);
/* Reset evbase */
void evkqueue_reset(EVBASE *evbase);
/* Clean evbase */
void evkqueue_clean(EVBASE *evbase);
#endif
#endif

