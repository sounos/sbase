#include "evbase.h"
#ifdef HAVE_EVRTSIG
#ifndef _EVRTSIG_H
#define _EVRTSIG_H
/* Initialize evrtsig  */
int evrtsig_init(EVBASE *evbase);
/* Add new event to evbase */
int evrtsig_add(EVBASE *evbase, EVENT *event);
/* Update event in evbase */
int evrtsig_update(EVBASE *evbase, EVENT *event);
/* Delete event from evbase */
int evrtsig_del(EVBASE *evbase, EVENT *event);
/* Loop evbase */
int evrtsig_loop(EVBASE *evbase, int, struct timeval *tv);
/* Reset evbase */
void evrtsig_reset(EVBASE *evbase);
/* Clean evbase */
void evrtsig_clean(EVBASE *evbase);
#endif
#endif

