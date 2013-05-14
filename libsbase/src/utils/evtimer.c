#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include "xmm.h"
#include "evtimer.h"
#include "mutex.h"
/* evtimer push */
void evtimer_push(EVTIMER *evtimer, EVTNODE *node)
{
    EVTNODE *tmp = NULL;
    int evid = 0;

    if(evtimer && node)
    {
        evid = node->id;
        node->next = node->prev = NULL;
        if(evtimer->tail  == NULL || evtimer->head == NULL)
            evtimer->head = evtimer->tail = node;
        else
        {
            if(node->evusec >= evtimer->tail->evusec)
            {
                node->prev = evtimer->tail;
                evtimer->tail->next = node;
                evtimer->tail = node;
            }
            else if(node->evusec < evtimer->head->evusec)
            {
                node->next = evtimer->head;
                evtimer->head->prev = node;
                evtimer->head = node;
            }
            else
            {
                tmp = evtimer->tail->prev;
                while(tmp && tmp->evusec > node->evusec)
                    tmp = tmp->prev;
                if(tmp)
                {
                    node->next = tmp->next;
                    node->prev = tmp;
                    tmp->next = node;
                    node->next->prev = node;
                }
            }
        }
    }
    return ;
}

/* add event timer */
int evtimer_add(EVTIMER *evtimer, off_t timeout, EVTCALLBACK *handler, void *arg)
{
    struct timeval tv = {0};
    EVTNODE *node = NULL;
    int evid = -1;

    if(evtimer && handler && timeout > 0)
    {
        MUTEX_LOCK(evtimer->mutex);
        if((node = evtimer->left))
        {
            evtimer->left = node->next; 
            evid = node->id;
            node->handler = handler;
            node->arg = arg;
            node->ison = 1;
            gettimeofday(&tv, NULL);
            node->evusec = (off_t)(tv.tv_sec * 1000000ll + tv.tv_usec * 1ll) + timeout;
            evtimer_push(evtimer, node);
        }
        MUTEX_UNLOCK(evtimer->mutex);
    }
    return evid;
}

/* update event timer */
int evtimer_update(EVTIMER *evtimer, int evid, off_t timeout, EVTCALLBACK *handler, void *arg)
{
    struct timeval tv = {0};
    EVTNODE *node = NULL;
    int i = 0, ret = -1;

    if(evtimer &&  (i = evid) > 0 && evid < EVTNODE_MAX)
    {
        MUTEX_LOCK(evtimer->mutex);
        if((node = &(evtimer->nodes[i])) && node->ison)
        {
            if(node->prev) node->prev->next = node->next;
            if(node->next) node->next->prev = node->prev;
            if(node == evtimer->head) evtimer->head = node->next;
            if(node == evtimer->tail) evtimer->tail = node->prev;
            node->handler = handler;
            node->arg = arg;
            gettimeofday(&tv, NULL);
            node->evusec = (off_t)(tv.tv_sec * 1000000ll + tv.tv_usec * 1ll) + timeout;
            evtimer_push(evtimer, node);
            ret = 0;
        }
        MUTEX_UNLOCK(evtimer->mutex);
    }
    return ret;
}

/* delete event timer */
int evtimer_delete(EVTIMER *evtimer, int evid)
{
    EVTNODE *node = NULL;
    int ret = -1, i = 0;

    if(evtimer && (i = evid) > 0 && evid < EVTNODE_MAX)
    {
        MUTEX_LOCK(evtimer->mutex);
        if((node = &(evtimer->nodes[i])) && node->ison)
        {
            if(node->prev) node->prev->next = node->next;
            if(node->next) node->next->prev = node->prev;
            if(node == evtimer->head) evtimer->head = node->next;
            if(node == evtimer->tail) evtimer->tail = node->prev;
            memset(node, 0, sizeof(EVTNODE));
            node->id = evid;
            node->next = evtimer->left;
            evtimer->left = node;
        }
        MUTEX_UNLOCK(evtimer->mutex);
    }
    return ret;
}

/* check timeout */
void evtimer_check(EVTIMER *evtimer)
{
    EVTCALLBACK *handler = NULL;
    struct timeval tv = {0};
    EVTNODE *node = NULL;
    int i = 0, id = 0;
    off_t now = 0;

    if(evtimer && evtimer->head)
    {
        gettimeofday(&tv, NULL);
        now = (off_t)(tv.tv_sec * 1000000ll + tv.tv_usec * 1ll);
        MUTEX_LOCK(evtimer->mutex);
        evtimer->ntimeout = 0;
        while((node = evtimer->head) && node->evusec < now)
        {
            if((evtimer->head = node->next))
                evtimer->head->prev = NULL;
            else
                evtimer->tail = NULL;
            evtimer->timeouts[evtimer->ntimeout++] = node->id;
            node->next = node->prev = NULL;
        }
        MUTEX_UNLOCK(evtimer->mutex);
        for(i = 0; i < evtimer->ntimeout; i++)
        {
            if((id = evtimer->timeouts[i]) && (node = &(evtimer->nodes[id])) 
                    && node->next == NULL && node->prev == NULL
                    && node->ison && (handler = node->handler))
                handler(node->arg);
        }
    }
    return ;
}

/* reset evtimer */
void evtimer_reset(EVTIMER *evtimer)
{
    EVTNODE *tmp = NULL, *node = NULL;
    int id = -1;

    if(evtimer && (node = evtimer->head))
    {
        do
        {
            id = node->id;
            tmp = node; 
            node = node->next;
            memset(tmp, 0, sizeof(EVTNODE));
            tmp->id = id;
            tmp->next = evtimer->left;
            evtimer->left = tmp;
        }while(node);
    }
    return ;
}

/* clean evtimer */
void evtimer_clean(EVTIMER *evtimer)
{
    int i = 0;

    if(evtimer)
    {
        MUTEX_DESTROY(evtimer->mutex);
        /*
        for(i = 0; i < evtimer->nevlist; i++)
        {
            xmm_free(evtimer->evlist[i], sizeof(EVTNODE) * EVTNODE_LINE_NUM);
        }
        */
        xmm_free(evtimer, sizeof(EVTIMER));
    }

    return ;
}

/* intialize evtimer */
EVTIMER *evtimer_init()
{
    EVTIMER *evtimer = NULL;
    EVTNODE *node = NULL;
    int i = 0;

    if((evtimer = (EVTIMER *)xmm_mnew(sizeof(EVTIMER))))
    {
        MUTEX_INIT(evtimer->mutex);
        for(i = 1; i < EVTNODE_MAX; i++)
        {
            node = &(evtimer->nodes[i]);
            node->next = evtimer->left;
            node->id = i;
            evtimer->left = node;
        }
    }
    return evtimer;
}

#ifdef _DEBUG_EVTIMER
void evtimer_handler(void *arg)
{
    fprintf(stdout, "active evtimer\n"); 
    return ;
}
int main()
{
    EVTIMER *evtimer = NULL;
    int i = 0, id = 0, max = 1000000;
    off_t timeout = 10000000;

    if((evtimer = evtimer_init()))
    {
        for(i = 0; i < max; i++)
        {
            timeout = random()%1000000000;
            id = evtimer_add(evtimer, timeout, &evtimer_handler, NULL); 
            fprintf(stdout, "%d:%lu\n", id, (unsigned long)(timeout));
        }
        fprintf(stdout, "starting check()");
        evtimer_check(evtimer);
        fprintf(stdout, "over check()");
        evtimer_reset(evtimer);
        fprintf(stdout, "over reset()");
        evtimer_clean(evtimer);
    }
    return 0;
}
#endif
