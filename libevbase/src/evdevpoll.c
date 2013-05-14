#include "evdevpoll.h"
#ifdef HAVE_DEVPOLL
#include <sys/resource.h>
/* Initialize evdevpoll  */
int evdevpoll_init(EVBASE *evbase)
{
    return 0;
}
/* Add new event to evbase */
int evdevpoll_add(EVBASE *evbase, EVENT *event)
{
    return 0;
}
/* Update event in evbase */
int evdevpoll_update(EVBASE *evbase, EVENT *event)
{
    return 0;
}
/* Delete event from evbase */
int evdevpoll_del(EVBASE *evbase, EVENT *event)
{
    return 0;
}
/* Loop evbase */
int evdevpoll_loop(EVBASE *evbase, int loop_flags, struct timeval *tv)
{
    return 0;
}
/* Reset evbase */
void evdevpoll_reset(EVBASE *evbase)
{
    return ;
}
/* Clean evbase */
void evdevpoll_clean(EVBASE *evbase)
{
    return;
}
#endif
