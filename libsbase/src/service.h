#include "sbase.h"
#include "chunk.h"
#ifndef _SERVICE_H
#define _SERVICE_H
#ifdef __cplusplus
extern "C" {
#endif
/* set service */
int service_set(SERVICE *service);
/* run service */
int service_run(SERVICE *service);
/* stop service */
void service_stop(SERVICE *service);
/* new proxy */
CONN *service_newproxy(SERVICE *service, CONN *parent, int inet_family, int socket_type, 
        char *ip, int port, SESSION *session);
/* new connection */
CONN *service_newconn(SERVICE *service, int inet_family, int socket_type, 
        char *ip, int port, SESSION *session);
/* add new connection */
CONN *service_addconn(SERVICE *service, int sock_type, int fd, 
        char *remote_ip, int remote_port, char *local_ip, int local_port, 
        SESSION *session, void *ssl, int status);
/* push connection to connections pool */
int service_pushconn(SERVICE *service, CONN *conn);
/* set connection status ok */
int service_okconn(SERVICE *service, CONN *conn);
/* pop connection from connections pool */
int service_popconn(SERVICE *service, CONN *conn);
/* get free connection */
CONN *service_getconn(SERVICE *service, int groupid);
/* find connection as index */
CONN *service_findconn(SERVICE *service, int index);
/* service over conn */
void service_overconn(SERVICE *service, CONN *conn);
/* pop chunk from service  */
CHUNK *service_popchunk(SERVICE *service);
/* push to qconns */
int service_pushtoq(SERVICE *service, CONN *conn);
/* push to qconn */
CONN *service_popfromq(SERVICE *service);
/* push chunk to service  */
int service_pushchunk(SERVICE *service, CHUNK *cp);
/* new chunk */
CB_DATA *service_newchunk(SERVICE *service, int len);
/* new chunk and memset */
CB_DATA *service_mnewchunk(SERVICE *service, int len);
/* set service session */
int service_set_session(SERVICE *service, SESSION *session);
/* add multicast */
int service_add_multicast(SERVICE *service, char *multicast_ip);
/* drop multicast */
int service_drop_multicast(SERVICE *service, char *multicast_ip);
/* broadcast */
int service_broadcast(SERVICE *service, char *data, int len);
/* add group */
int service_addgroup(SERVICE *service, char *ip, int port, int limit, SESSION *session);
/* close group */
int service_closegroup(SERVICE *service, int groupid);
/* group cast */
int service_castgroup(SERVICE *service, char *data, int len);
/* state groups */
int service_stategroup(SERVICE *service);
/* new task */
int service_newtask(SERVICE *service, CALLBACK *callback, void *arg);
/* add new transaction */
int service_newtransaction(SERVICE *service, CONN *conn, int tid);
/* set log */
int service_set_log(SERVICE *service, char *logfile);
/* accept handler */
int service_accept_handler(SERVICE *service, int evfd);
/* event handler */
void service_event_handler(int, int, void *);
/* heartbeat handler */
void service_set_heartbeat(SERVICE *service, int interval, CALLBACK *handler, void *arg);
/* state check */
void service_state(void *arg);
/* active heartbeat */
void service_active_heartbeat(void *arg);
/* active evtimer heartbeat */
void service_evtimer_handler(void *arg);
/* clean service */
void service_clean(SERVICE *service);
#ifdef __cplusplus
 }
#endif
#endif
