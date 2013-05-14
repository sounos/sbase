#include "evbase.h"
#ifdef HAVE_EVPORT
#ifndef _EVPORT_H
#define _EVPORT_H
/* Initialize evport  */
int evport_init(EVBASE *evbase);
/* Add new event to evbase */
int evport_add(EVBASE *evbase, EVENT *event);
/* Update event in evbase */
int evport_update(EVBASE *evbase, EVENT *event);
/* Delete event from evbase */
int evport_del(EVBASE *evbase, EVENT *event);
/* Reset evbase */
void evport_reset(EVBASE *evbase);
/* Loop evbase */
int evport_loop(EVBASE *evbase, int, struct timeval *tv);
#endif
#endif

