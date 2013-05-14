#include "evport.h"
#ifdef HAVE_EVPORT
#include <sys/resource.h>
/* Initialize evport  */
int evport_init(EVBASE *evbase)
{
    return -1;
}
/* Add new event to evbase */
int evport_add(EVBASE *evbase, EVENT *event)
{
    return -1;
}
/* Update event in evbase */
int evport_update(EVBASE *evbase, EVENT *event)
{
    return -1;
}
/* Delete event from evbase */
int evport_del(EVBASE *evbase, EVENT *event)
{
    return -1;
}
/* Loop evbase */
int evport_loop(EVBASE *evbase, int loop_flags, struct timeval *tv)
{
    return -1;
}
/* Reset evbase */
void evport_reset(EVBASE *evbase)
{
    return ;
}
/* Clean evbase */
int evport_clean(EVBASE *evbase)
{
    return -1;
}
#endif

