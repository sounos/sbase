#include "sbase.h"
#ifndef _PROCTHREAD_H
#define _PROCTHREAD_H
PROCTHREAD *procthread_init(int cond);

/* set evsig */
void procthread_set_evsig_fd(PROCTHREAD *pth, int fd);

/* run procthread */
void procthread_run(void *arg);

/* add new task */
int procthread_newtask(PROCTHREAD *pth, CALLBACK *, void *arg);

/* add new transaction */
int procthread_newtransaction(PROCTHREAD *pth, CONN *, int tid);

/* push new connection*/
int procthread_pushconn(PROCTHREAD *, int fd, void *ssl);

/* add new connection*/
int procthread_newconn(PROCTHREAD *, int fd, void *ssl);

/* Add connection message */
int procthread_addconn(PROCTHREAD *, CONN *);

/* Add new connection */
int procthread_add_connection(PROCTHREAD *, CONN *);

/* Shut connection */
int procthread_shut_connection(PROCTHREAD *, CONN *);

/* Over connection */
int procthread_over_connection(PROCTHREAD *, CONN *);

/* Terminate connection */
int procthread_terminate_connection(PROCTHREAD *, CONN *);

/* Add stop message on procthread */
void procthread_stop(PROCTHREAD *);

/* Terminate procthread */
void procthread_terminate(PROCTHREAD *);

/* state */
void procthread_state(PROCTHREAD *,  CALLBACK *handler, void *arg);

/* active heartbeat */
void procthread_active_heartbeat(PROCTHREAD *,  CALLBACK *handler, void *arg);

/* Clean procthread */
void procthread_clean(PROCTHREAD *);
#endif
