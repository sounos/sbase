#include "evwin32.h"
#ifdef WIN32
/* Initialize evwin32  */
int evwin32_init(EVBASE *evbase)
{
    return -1;
}
/* Add new event to evbase */
int evwin32_add(EVBASE *evbase, EVENT *event)
{
    return -1;
}
/* Update event in evbase */
int evwin32_update(EVBASE *evbase, EVENT *event)
{
    return -1;
}
/* Delete event from evbase */
int evwin32_del(EVBASE *evbase, EVENT *event)
{
    return -1;
}
/* Loop evbase */
int evwin32_loop(EVBASE *evbase, int loop_flags, struct timeval *tv)
{
    return -1;
}
/* Reset evbase */
void evwin32_reset(EVBASE *evbase)
{
    return ;
}
/* Clean evbase */
void evwin32_clean(EVBASE *evbase)
{
    return ;
}
#endif
