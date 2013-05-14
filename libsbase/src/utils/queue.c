#include <stdio.h>
#include "xmm.h"
#include "mutex.h"
#include "queue.h"

void *queue_init()
{
    QNODE *tmp = NULL;
    QUEUE *q = NULL;
    int j = 0;

    if((q = (QUEUE *)xmm_mnew(sizeof(QUEUE)))) 
    {
        MUTEX_INIT(q->mutex);
        j = 0;
        while(j  < QNODE_LINE_NUM)
        {
            tmp = &(q->nodes[j]);
            tmp->next = q->left;
            q->left = tmp;
            q->nleft++;
            ++j;
        }
    }
    return q;
}

QNODE *queue_new(void *queue)
{
    QNODE *node = NULL, *tmp = NULL, *nodes = NULL;
    QUEUE *q = (QUEUE *)queue;
    int k = 0, j = 0;

    MUTEX_LOCK(q->mutex);
    if((node = q->left))
    {
        q->left = node->next;
        q->nleft--;
    }
    else 
    {
        if((k = q->nlist) < QNODE_LINE_MAX 
                && (nodes = (QNODE *)xmm_new(QNODE_LINE_NUM * sizeof(QNODE))))
        {
            q->list[k] = nodes;
            q->nlist++;
            j = 1;
            while(j  < QNODE_LINE_NUM)
            {
                tmp = &(nodes[j]);
                tmp->next = q->left;
                q->left = tmp;
                q->nleft++;
                ++j;
            }
            q->qtotal += QNODE_LINE_NUM;
            node = nodes;
        }
    }
    MUTEX_UNLOCK(q->mutex);
    return node;
}

void queue_push(void *queue, void *ptr)
{
    QUEUE *q = (QUEUE *)queue;
    QNODE *node = NULL;

    if(q)
    {
        if((node = queue_new(queue)))
        {
            MUTEX_LOCK(q->mutex);
            node->ptr = ptr;
            if(q->last)
            {
                q->last->next = node;
                q->last = node;
            }
            else
            {
                q->first = q->last = node;
            }
            node->next = NULL;
            q->total++;
            MUTEX_UNLOCK(q->mutex);
        }
    }
    return ;
}


int queue_total(void *queue)
{
    QUEUE *q = (QUEUE *)queue;
    int ret = -1;

    if(q)
    {
        ret = q->total;
    }
    return ret;
}


void *queue_head(void *queue)
{
    QUEUE *q = (QUEUE *)queue;
    QNODE *node = NULL;
    void *ptr = NULL;

    if(q)
    {
        if((node = q->first))
        {
            ptr = node->ptr;
        }
    }
    return ptr;
}

void *queue_pop(void *queue)
{
    QUEUE *q = (QUEUE *)queue;
    QNODE *node = NULL;
    void *ptr = NULL;

    if(q)
    {
        MUTEX_LOCK(q->mutex);
        if((node = q->first))
        {
            ptr = node->ptr;
            if((q->first = q->first->next) == NULL)
            {
                q->last = NULL;
            }
            node->next = q->left;
            q->left = node;
            q->nleft++;
            --(q->total);
        }
        MUTEX_UNLOCK(q->mutex);
    } 
    return ptr;
}

void queue_clean(void *queue)
{
    QUEUE *q = (QUEUE *)queue;
    int i = 0;

    if(q)
    {
        //fprintf(stdout, "%s::%d q:%p nleft:%d qtotal:%d qleft:%p\n", __FILE__, __LINE__, q, q->nleft, q->qtotal, q->left);
        for(i = 0; i < q->nlist; i++);
        {
            xmm_free(q->list[i], QNODE_LINE_NUM * sizeof(QNODE));
        }
        MUTEX_DESTROY(q->mutex);
        xmm_free(q, sizeof(QUEUE));
    }
    return ;
}
