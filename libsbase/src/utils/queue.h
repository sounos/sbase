#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "mutex.h"
#ifndef _QUEUE_H
#define _QUEUE_H
#ifdef __cplusplus
extern "C" {
#endif
typedef struct _QNODE
{
    void *ptr;
    struct _QNODE *next;
}QNODE;
#define QNODE_LINE_MAX   1024
#define QNODE_LINE_NUM   1024
typedef struct _QUEUE
{
    int nleft;
    int qtotal;
    int total;
    int nlist;
    MUTEX *mutex;
    QNODE *left;
    QNODE *first;
    QNODE *last;
    QNODE nodes[QNODE_LINE_NUM];
    QNODE *list[QNODE_LINE_MAX];
}QUEUE;
void *queue_init();
int  queue_total(void *q);
void queue_push(void *q, void *ptr);
void *queue_pop(void *q);
void *queue_head(void *q);
void queue_clean(void *q);
#define QTOTAL(q) (((QUEUE *)q)->total)
#define QQTOTAL(q) (((QUEUE *)q)->qtotal)
#ifdef __cplusplus
     }
#endif
#endif
