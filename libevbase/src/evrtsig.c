#include "evrtsig.h"
#ifdef HAVE_EVRTSIG
#include <signal.h>
#include <sys/resource.h>
/* Initialize evrtsig  */
int evrtsig_init(EVBASE *evbase)
{
    return -1;
}
/* Add new event to evbase */
int evrtsig_add(EVBASE *evbase, EVENT *event)
{
    return -1;
}
/* Update event in evbase */
int evrtsig_update(EVBASE *evbase, EVENT *event)
{
    return -1;
}
/* Delete event from evbase */
int evrtsig_del(EVBASE *evbase, EVENT *event)
{
    return -1;
}
/* Loop evbase */
int evrtsig_loop(EVBASE *evbase, int flag, struct timeval *tv)
{
    return -1;
}
/* Reset evbase */
void evrtsig_reset(EVBASE *evbase)
{
    return ;
}
/* Clean evbase */
void evrtsig_clean(EVBASE *evbase)
{
    return ;
}
#endif
