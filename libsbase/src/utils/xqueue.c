#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "xmm.h"
#include "mutex.h"
#include "xqueue.h"

void *xqueue_init()
{
    XQUEUE *q = NULL;
    int i = 0, j = 0;

    if((q = (XQUEUE *)xmm_mnew(sizeof(XQUEUE)))) 
    {
        //memset(q, 0, sizeof(XQUEUE));
        for(i = 1; i < XQ_ROOTS_MAX; i++)
        {
            q->waits[j++] = i;
            q->nwaits++;
        }
        MUTEX_INIT(q->mutex);
    }
    return q;
}

/* new queue */
int xqueue_new(void *xqueue)
{
    XQUEUE *q = (XQUEUE *)xqueue;
    int qid = -1;

    if(q)
    {
        MUTEX_LOCK(q->mutex);
        if(q->nwaits > 0)
        {
            qid = q->waits[--(q->nwaits)];
            q->roots[qid].status = 1;
        }
        MUTEX_UNLOCK(q->mutex);
    }
    return qid;
}

int xqueue_total(void *xqueue, int qid)
{
    XQUEUE *q = (XQUEUE *)xqueue;
    XQROOT *root = NULL;
    int total = 0;

    if(q && qid > 0 && qid < XQ_ROOTS_MAX && (root = &(q->roots[qid])))
    {
        total =  root->total;
    }
    return total;
}

/* new queue */
void xqueue_close(void *xqueue, int qid)
{
    XQUEUE *q = (XQUEUE *)xqueue;
    XQNODE *node = NULL;
    XQROOT *root = NULL;

    if(q && qid > 0 && qid < XQ_ROOTS_MAX && (root = &(q->roots[qid])))
    {
        MUTEX_LOCK(q->mutex);
        while((node = root->first)) 
        {
            root->first = node->next;
            node->next = q->left;
            q->left = node;
        }
        memset(root, 0, sizeof(XQROOT));
        q->waits[q->nwaits++] = qid;
        MUTEX_UNLOCK(q->mutex);
    }
    return ;
}


void xqueue_push(void *xqueue, int qid, void *ptr)
{
    XQNODE *node = NULL, *nodes = NULL;
    XQUEUE *q = (XQUEUE *)xqueue;
    XQROOT *root = NULL;
    int i = 0;

    if(q)
    {
        if(q && qid > 0 && qid < XQ_ROOTS_MAX && (root = &(q->roots[qid])))
        {
            MUTEX_LOCK(q->mutex);
            if((node = q->left))
            {
                q->left = node->next;
                q->nleft--;
            }
            else 
            {
                if((nodes = (XQNODE *)xmm_mnew(sizeof(XQNODE) * XQ_NODES_MAX)))
                {
                    q->list[q->nlist++] = nodes;
                    for(i = 1; i < XQ_NODES_MAX; i++)
                    {
                        nodes[i].next = q->left;
                        q->left = &nodes[i];
                    }
                    node = &(nodes[0]);
                }
                else
                {
                    //fprintf(stderr, xmm_new failed, %s\n", strerror(errno));
                }
            }
            if(node)
            {
                node->ptr = ptr;
                if(root->last)
                {
                    root->last->next = node;
                    root->last = node;
                }
                else
                {
                    root->first = root->last = node;
                }
                node->next = NULL;
                root->total++;
            }
            MUTEX_UNLOCK(q->mutex);
        }
    }
    return ;
}

void *xqueue_head(void *xqueue, int qid)
{
    XQUEUE *q = (XQUEUE *)xqueue;
    XQROOT *root = NULL;
    XQNODE *node = NULL;
    void *ptr = NULL;

    if(q && qid > 0 && qid < XQ_ROOTS_MAX && (root = &(q->roots[qid])))
    {
        if((node = root->first))
        {
            ptr = node->ptr;
        }
    }
    return ptr;
}

void *xqueue_pop(void *xqueue, int qid)
{
    XQUEUE *q = (XQUEUE *)xqueue;
    XQNODE *node = NULL;
    XQROOT *root = NULL;
    void *ptr = NULL;

    if(q && qid > 0 && qid < XQ_ROOTS_MAX && (root = &(q->roots[qid])))
    {
        MUTEX_LOCK(q->mutex);
        if((node = root->first))
        {
            ptr = node->ptr;
            if((root->first = root->first->next) == NULL)
            {
                root->last = NULL;
            }
            node->next = q->left;
            q->left = node;
            q->nleft++;
            --(root->total);
        }
        MUTEX_UNLOCK(q->mutex);
    } 
    return ptr;
}

void xqueue_clean(void *xqueue)
{
    XQUEUE *q = (XQUEUE *)xqueue;
    XQNODE *node = NULL;
    int i = 0;

    if(q)
    {
        //fprintf(stdout, "%s::%d q:%p nleft:%d qtotal:%d qleft:%p\n", __FILE__, __LINE__, q, q->nleft, q->qtotal, q->left);
        for(i = 0; i < q->nlist; i++);
        {
            if(q->list[i]) 
                xmm_free(q->list[i], XQ_NODES_MAX * sizeof(XQNODE));
        }
        /*
       while((node = q->left))
       {
           q->left = node->next;
           xmm_free(node, sizeof(XQNODE));
       }
       */
        MUTEX_DESTROY(q->mutex);
        xmm_free(q, sizeof(XQUEUE));
    }
    return ;
}
