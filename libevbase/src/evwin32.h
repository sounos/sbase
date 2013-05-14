#include "evbase.h"
#ifdef WIN32
#ifndef _EVWIN32_H
#define _EVWIN32_H
/* Initialize evwin32  */
int evwin32_init(EVBASE *evbase);
/* Add new event to evbase */
int evwin32_add(EVBASE *evbase, EVENT *event);
/* Update event in evbase */
int evwin32_update(EVBASE *evbase, EVENT *event);
/* Delete event from evbase */
int evwin32_del(EVBASE *evbase, EVENT *event);
/* Loop evbase */
int evwin32_loop(EVBASE *evbase, int, struct timeval *tv);
/* Reset evbase */
void evwin32_reset(EVBASE *evbase);
/* Clean evbase */
void evwin32_clean(EVBASE *evbase);
#endif
#endif

