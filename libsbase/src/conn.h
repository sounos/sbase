#include "sbase.h"
#ifndef _CONN_H
#define _CONN_H

/* set connection */
int conn_set(CONN *conn);

/* close connection */
int conn_close(CONN *conn);

/* over connection */
int conn_over(CONN *conn);

/* terminate connection */
int conn_terminate(CONN *conn);

/* set timeout */
int conn_set_timeout(CONN *conn, int timeout_usec);

/* over timeout */
int conn_over_timeout(CONN *conn);

/* set evstate as wait */
int conn_wait_evstate(CONN *conn);

/* over evstate */
int conn_over_evstate(CONN *conn);

/* set session parent */
int conn_set_session_parent(CONN *conn,void *);

/* set session child */
int conn_set_session_child(CONN *conn,void *);

/* start client transaction state */
int conn_start_cstate(CONN *conn);

/* over client transaction state */
int conn_over_cstate(CONN *conn);

/* push message to message queue */
int conn_push_message(CONN *conn, int message_id);

/* read handler */
int conn_read_handler(CONN *conn);

/* write handler */
int conn_write_handler(CONN *conn);

/* packet reader */
int conn_packet_reader(CONN *conn);

/* packet handler */
int conn_packet_handler(CONN *conn);

/* oob data handler */
int conn_oob_handler(CONN *conn);

/* chunk data  handler */
int conn_data_handler(CONN *conn);

/* bind proxy */
int conn_bind_proxy(CONN *conn, CONN *child);

/* proxy data handler */
int conn_proxy_handler(CONN *conn);

/* close proxy */
int conn_close_proxy(CONN *conn);

/* push to exchange  */
int conn_push_exchange(CONN *conn, void *data, int size);

/* save cache to connection  */
int conn_save_cache(CONN *conn, void *data, int size);

/* read chunk */
int conn__read__chunk(CONN *conn);

/* chunk reader */
int conn_chunk_reader(CONN *conn);

/* receive chunk */
int conn_recv_chunk(CONN *conn, int size);

/* receive and fill to chunk */
int conn_recv2_chunk(CONN *conn, int size, char *data, int ndata);

/* push chunk */
int conn_push_chunk(CONN *conn, void *chunk_data, int size);

/* over chunk */
int conn_over_chunk(CONN *conn);

/* pop chunk */
CHUNK* conn_popchunk(CONN *conn);

/* newchunk */
CB_DATA* conn_newchunk(CONN *conn, int size);

/* newchunk & memset */
CB_DATA* conn_mnewchunk(CONN *conn, int size);

/* freechunk */
void conn_freechunk(CONN *conn, CB_DATA *chunk);

/* set chunk to chunk2 */
void conn_setto_chunk2(CONN *conn);

/* reset chunk2 */
void conn_reset_chunk2(CONN *conn);

/* receive chunk file */
int conn_recv_file(CONN *conn, char *file, long long offset, long long size);

/* store chunk */
int conn_store_chunk(CONN *conn, char *block, int size);

/* push chunk file */
int conn_push_file(CONN *conn, char *file, long long offset, long long size);

/* send chunk */
int conn_send_chunk(CONN *conn, CB_DATA *chunk, int len);

/* relay chunk */
int conn_relay_chunk(CONN *conn, CB_DATA *chunk, int len);

/* set session options */
int conn_set_session(CONN *conn, SESSION *session);

/* over session */
int conn_over_session(CONN *conn);

/* new task */
int conn_newtask(CONN *conn, CALLBACK *);

/* add multicast */
int conn_add_multicast(CONN *conn, char *ip);

/* transaction handler */
int conn_transaction_handler(CONN *conn, int tid);

/* timeout handler */
int conn_timeout_handler(CONN *conn);

/* evtimer handler */
void conn_evtimer_handler(void *arg);

/* reset xids */
void conn_reset_xids(CONN *conn);

/* reset state */
void conn_reset_state(CONN *conn);

/* reset conn */
void conn_reset(CONN *conn);

/* clean connection */
void conn_clean(CONN *conn);

/* event handler */
void conn_event_handler(int event_fd, int event, void *arg);
#endif
