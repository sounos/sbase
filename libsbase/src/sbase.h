#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pthread.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <evbase.h>
#ifndef _SBASE_H
#define _SBASE_H
#ifdef __cplusplus
extern "C" {
#endif
#define SB_CONN_MAX             40960
#define SB_GROUP_CONN_MAX       512
#define SB_BACKLOG_MAX          40960
#define SB_IP_MAX               16
#define SB_XIDS_MAX             16
#define SB_GROUPS_MAX           1024
#define SB_SERVICE_MAX          256
#define SB_THREADS_MAX          256
#define SB_INIT_CONNS           256
#define SB_INIT_CHUNKS          256
#define SB_CONNS_LIMIT          256
#define SB_QCONN_MAX            256
#define SB_CHUNKS_MAX           256
#define SB_QBLOCK_MAX           16
#define SB_BUF_SIZE             65536
#define SB_USEC_SLEEP           1000
#define SB_PROXY_TIMEOUT        20000000
#define SB_HEARTBEAT_INTERVAL   1000000
#define SB_NWORKING_TOSLEEP     20000
#define SB_SCHED_FIFO           0x01
#define SB_SCHED_RR             0x02
#define SB_TCP_NODELAY          0x04
#define SB_LOG_THREAD           0x08
#define SB_IO_NANOSLEEP         0x10
#define SB_IO_USLEEP            0x20
#define SB_IO_SELECT            0x40
#define SB_EVENT_LOCK           0x80
#define SB_WHILE_SEND           0x100
#define SB_SO_LINGER            0x200
#define SB_USE_OUTDAEMON        0x400
#define SB_USE_EVSIG            0x800
#define SB_USE_COND             0x1000
#define SB_SCHED_REALTIME       0x2000
#define SB_CPU_SET              0x4000
#define SB_NEWCONN_DELAY        0x8000
#define SB_MULTICAST_IN         0x01
#define SB_MULTICAST_MAX        256
#define SB_SSLCERTS_MAX         256
/* service type */
#define S_SERVICE               0x00
#define C_SERVICE               0x01
/* working mode */
#define WORKING_PROC            0x00
#define WORKING_THREAD          0x01
#define THREAD_EVBASE           0x01 
#define THREAD_MESSAGEQ         0x02
/* connection status */
#define CONN_STATUS_FREE        0x00
#define CONN_STATUS_READY       0x01
#define CONN_STATUS_CONNECTED   0x02
#define CONN_STATUS_WORKING     0x04
#define CONN_STATUS_CLOSED      0x08
/* client running status */
#define C_STATE_FREE            0x00
#define C_STATE_WORKING         0x02
#define C_STATE_USING           0x04
#define C_STATE_OVER            0x08
/* ERROR wait state */
#define E_STATE_OFF             0x00
#define E_STATE_ON              0x01
/* connection running state */
#ifndef S_STATES
#define S_STATE_READY           0x00
#define S_STATE_READ_CHUNK      0x02
#define S_STATE_WRITE_STATE     0x04
#define S_STATE_PACKET_HANDLING 0x08
#define S_STATE_DATA_HANDLING   0x10
#define S_STATE_TASKING         0x20
#define S_STATE_CHUNK_READING   0x40
#define S_STATE_CLOSE           0x80
#define S_STATES                0xee
#endif
#ifndef D_STATES
#define D_STATE_FREE            0x00
#define D_STATE_RCLOSE          0x02
#define D_STATE_WCLOSE          0x04
#define D_STATE_CLOSE           0x08
#define D_STATES                0x0e
#endif
/* packet type list*/
#define PACKET_CUSTOMIZED       0x01
#define PACKET_CERTAIN_LENGTH   0x02
#define PACKET_DELIMITER        0x04
#define PACKET_PROXY            0x08
#define PACKET_ALL              0x0f
#define SB_COND_FILE            "/tmp/sbase_cond"
struct _SBASE;
struct _SERVICE;
struct _PROCTHREAD;
struct _CONN;
#ifndef __TYPEDEF__MMBLOCK
#define __TYPEDEF__MMBLOCK
typedef struct _MMBLOCK
{
    char *data;
    int  ndata;
    int  size;
    int  left;
    int  bits;
    char *end;
}MMBLOCK;
#endif
#ifndef __TYPEDEF__CHUNK
#define __TYPEDEF__CHUNK
#define CHUNK_FILE_NAME_MAX     256
typedef struct _CHUNK
{
    char *data;
    int  ndata;
    int  status;
    int  bsize;
    int  type;
    int  fd;
    int  flag;
    off_t size;
    off_t offset;
    off_t left;
    off_t mmleft;
    off_t mmoff;
    char *mmap;
    char *end;
    char filename[CHUNK_FILE_NAME_MAX];
}CHUNK;
#endif
typedef struct _QBLOCK
{
    CHUNK chunk;
    struct _QBLOCK *next;
}QBLOCK;
typedef struct _CB_DATA
{
    char *data;
    int ndata;
    int size;
}CB_DATA;
#define PCB(mmm) ((CB_DATA *)((void *)&mmm))
#define SB_USE_SSL          0x01
#define SB_USE_OOB          0x02
#define SB_MULTICAST        0x04
#define SB_NONBLOCK         0x08
#define SB_MULTICAST_LIST   0x10
typedef struct _SESSION
{
    /* SSL/timeout */
    int  flags;
    int  timeout;
    int  childid;
    int  parentid;
    int  packet_type;
    int  packet_length;
    int  packet_delimiter_length;
    int  buffer_size;
    int  groupid;
    int  multicast_ttl;
    int  xids[SB_XIDS_MAX];

    void *child;
    void *ctx;
    void *ssl_servername_arg;
    void *parent;
    char *packet_delimiter;

    /* methods */
    int (*welcome_handler)(struct _CONN *);
    int (*quick_handler)(struct _CONN *, CB_DATA *packet);
    int (*error_handler)(struct _CONN *, CB_DATA *packet, CB_DATA *cache, CB_DATA *chunk);
    int (*packet_reader)(struct _CONN *, CB_DATA *buffer);
    int (*packet_handler)(struct _CONN *, CB_DATA *packet);
    int (*data_handler)(struct _CONN *, CB_DATA *packet, CB_DATA *cache, CB_DATA *chunk);
    int (*chunk_reader)(struct _CONN *, CB_DATA *buffer);
    int (*chunk_handler)(struct _CONN *, CB_DATA *packet, CB_DATA *cache, CB_DATA *chunk);
    int (*file_handler)(struct _CONN *, CB_DATA *packet, CB_DATA *cache, char *file);
    int (*oob_handler)(struct _CONN *, CB_DATA *oob);
    int (*timeout_handler)(struct _CONN *, CB_DATA *packet, CB_DATA *cache, CB_DATA *chunk);
    int (*evtimeout_handler)(struct _CONN *);
    int (*transaction_handler)(struct _CONN *, int tid);
    int (*ok_handler)(struct _CONN *);
    int (*sendover_handler)(struct _CONN *);
    int (*exchange_handler)(struct _CONN *, CB_DATA *exchange);
    int (*ssl_servername_handler)(void *ssl, int *, void *arg);
}SESSION;

typedef void (CALLBACK)(void *);
typedef struct _SBASE
{
    /* base option */
    int nchilds;
    int connections_limit;
	int usec_sleep;
    int running_status;
    int running_services;
    int evlog_level;
    int cond;
    int bits;
    /* evtimer */
    int evid;
    int ssl_id;

    /* event */
    EVENT event;

	/* timer && logger */
	void *logger;
	EVBASE *evbase;
    char *evlogfile;
    void *evtimer;
    /* message queue for proc mode */
    void *message_queue;
    struct _SERVICE *services[SB_SERVICE_MAX];

	int  (*set_log)(struct _SBASE *, char *);
    int  (*set_log_level)(struct _SBASE *sbase, int level);
	int  (*set_evlog)(struct _SBASE *, char *);
	int  (*set_evlog_level)(struct _SBASE *, int level);
	
	int  (*add_service)(struct _SBASE *, struct _SERVICE *);
    int  (*run_service)(struct _SBASE *, struct _SERVICE *);
	void (*remove_service)(struct _SBASE *, struct _SERVICE *);
    int  (*running)(struct _SBASE *, int time_usec);
	void (*stop)(struct _SBASE *);
	void (*clean)(struct _SBASE *);
}SBASE;
/* Initialize sbase */
int setrlimiter(char *name, int rlimid, int nset);
SBASE *sbase_init();

/* group */
typedef struct _CNGROUP
{
  int   status;
  int   nconnected;
  int   port;
  int   limit;
  int   total;
  int   nconns_free;
  ushort   conns_free[SB_GROUP_CONN_MAX];
  char  ip[SB_IP_MAX];
  SESSION session;
}CNGROUP;
typedef struct _SSLCRTS
{
    char *name;
    char *cert;
    char *priv;
    void *ssl_cxt;
}SSLCRTS;
/* service */
typedef struct _SERVICE
{
    /* global */
    int id;
    int lock;
    int usec_sleep;
    int use_cond_wait;
    int nconn;
    int connections_limit; 
    int index_max;
    int running_connections;
    int nconns_free;
    int nconnections;
    int conns_limit;
    int nqchunks;
    int service_type;
    int fd;
    int backlog;
    int port;
    int sock_type;
    int family;
    int heartbeat_interval;
    int working_mode;
    int nprocthreads;
    int niodaemons;
    int ndaemons;
    int is_use_SSL;
    int nqconns;
    int ngroups;
    int evid;
    int is_inside_logger;
    int ntask;
    int cond;
    int flag;
    int nworking_tosleep;
    ushort conns_free[SB_CONN_MAX];

    struct  sockaddr_in sa;
    EVENT event;

    EVBASE *evbase;
    SBASE *sbase;
    /* mutex */
    void *mutex;

    /* heartbeat */
    void *heartbeat_arg;
    CALLBACK *heartbeat_handler;
    void (*set_heartbeat)(struct _SERVICE *, int interval, CALLBACK *handler, void *arg);
    void (*active_heartbeat)(struct _SERVICE *);
    void (*onrunning)(struct _SERVICE *);

    /* working mode */
    struct _PROCTHREAD *tracker;
    struct _PROCTHREAD *daemon;
    struct _PROCTHREAD *acceptor;
    struct _PROCTHREAD *outdaemon;
    struct _PROCTHREAD *iodaemons[SB_THREADS_MAX];
    struct _PROCTHREAD *procthreads[SB_THREADS_MAX];
    struct _PROCTHREAD *daemons[SB_THREADS_MAX];

    /* socket and inet addr option  */
    char *ip;
    int  is_multicastd;
    int  nmulticasts;
    EVENT evmulticasts[SB_MULTICAST_MAX];
    ushort multicasts[SB_MULTICAST_MAX];
        
    /* SSL */
    SSLCRTS ssl_certs[SB_SSLCERTS_MAX];
    char *cacert_file;
    char *privkey_file;
    void *s_ctx;
    void *c_ctx;

    /* service option */
    char *service_name;
    int  (*set)(struct _SERVICE *service);
    int  (*run)(struct _SERVICE *service);
    void (*stop)(struct _SERVICE *service);

    
    /* message queue for proc mode */
    void *message_queue;
    //void *xqueue;

    //void *chunks_queue;
    //CHUNK *qchunks[SB_CHUNKS_MAX];
    //CHUNK *(*popchunk)(struct _SERVICE *service);
    //int (*pushchunk)(struct _SERVICE *service, CHUNK *cp);
    //CB_DATA *(*newchunk)(struct _SERVICE *service, int len);
    //CB_DATA *(*mnewchunk)(struct _SERVICE *service, int len);

    /* connections option */
    struct _CONN *connections[SB_CONN_MAX];
    struct _CONN *qconns[SB_QCONN_MAX];

    /* C_SERVICE ONLY */
    struct _CONN *(*newproxy)(struct _SERVICE *service, struct _CONN * parent, int inet_family, 
            int sock_type, char *ip, int port, SESSION *session);
    struct _CONN *(*newconn)(struct _SERVICE *service, int inet_family, int sock_type, 
            char *ip, int port, SESSION *session);
    struct _CONN *(*addconn)(struct _SERVICE *service, int sock_type, int fd, 
            char *remote_ip, int remote_port, char *local_ip, int local_port, 
            SESSION *, void *ssl, int status);
    struct _CONN *(*getconn)(struct _SERVICE *service, int groupid);
    int     (*freeconn)(struct _SERVICE *service, struct _CONN *);
    int     (*pushconn)(struct _SERVICE *service, struct _CONN *conn);
    int     (*okconn)(struct _SERVICE *service, struct _CONN *conn);
    int     (*popconn)(struct _SERVICE *service, struct _CONN *conn);
    struct _CONN *(*findconn)(struct _SERVICE *service, int index);
    void    (*overconn)(struct _SERVICE *service, struct _CONN *conn);

    /* CAST */
    int (*new_multicast)(struct _SERVICE *service, char *multicast_ip);
    int (*add_multicast)(struct _SERVICE *service, char *multicast_ip);
    int (*drop_multicast)(struct _SERVICE *service, char *multicast_ip);
    int (*broadcast)(struct _SERVICE *service, char *data, int len);

    /* group */
    int (*addgroup)(struct _SERVICE *service, char *ip, int port, int limit, SESSION *session);
    int (*closegroup)(struct _SERVICE *service, int groupid);
    int (*castgroup)(struct _SERVICE *service, char *data, int len);
    int (*stategroup)(struct _SERVICE *service);
    
    /* evtimer */
    void *etimer;
    void *evtimer;
    
    /* timer and logger */
    void *logger;
    int (*set_log)(struct _SERVICE *service, char *logfile);
    int (*set_log_level)(struct _SERVICE *service, int level);

    /* transaction and task */
    int (*newtask)(struct _SERVICE *, CALLBACK *, void *arg); 
    int (*newtransaction)(struct _SERVICE *, struct _CONN *, int tid);

    /* service default session option */
    int (*set_session)(struct _SERVICE *, SESSION *);

    /* clean */
    void (*clean)(struct _SERVICE *pservice);
    void (*close)(struct _SERVICE *);
    SESSION session;
    CNGROUP groups[SB_GROUPS_MAX];
}SERVICE;
/* Initialize service */
SERVICE *service_init();
/* procthread */
typedef struct _PROCTHREAD
{
    /* global */
    int status; 
    int lock;
    int running_status;
	int usec_sleep;
    int index;
    int use_cond_wait;
    int cond;
    int have_evbase;
    int listenfd;
    int flag;
    pthread_t threadid;
    EVENT event;
    //EVENT acceptor;
    EVSIG evsig;

    void *mutex;
    void *evtimer;
    SERVICE *service;

    /* message queue */
    //void *xqueue;
    void *indaemon;
    void *outdaemon;
    void *inqmessage;
    void *outqmessage;
    void *message_queue;

    /* evbase */
    EVBASE *evbase;
    EVBASE *outevbase;

    /* connection */
    struct _CONN **connections;
    int (*pushconn)(struct _PROCTHREAD *procthread, int fd, void *ssl);
    int (*newconn)(struct _PROCTHREAD *procthread, int fd, void *ssl);
    int (*addconn)(struct _PROCTHREAD *procthread, struct _CONN *conn);
    int (*add_connection)(struct _PROCTHREAD *procthread, struct _CONN *conn);
    int (*shut_connection)(struct _PROCTHREAD *procthread, struct _CONN *conn);
    int (*over_connection)(struct _PROCTHREAD *procthread, struct _CONN *conn);
    int (*terminate_connection)(struct _PROCTHREAD *procthread, struct _CONN *conn);

    /* logger */
    void *logger;

    /* task and transaction */
    int (*newtask)(struct _PROCTHREAD *, CALLBACK *, void *arg); 
    int (*newtransaction)(struct _PROCTHREAD *, struct _CONN *, int tid);

    /* heartbeat */
    void (*active_heartbeat)(struct _PROCTHREAD *,  CALLBACK *handler, void *arg);
    void (*state)(struct _PROCTHREAD *,  CALLBACK *handler, void *arg);

    /* normal */
    void (*run)(void *arg);
    void (*set_acceptor)(struct _PROCTHREAD *procthread, int fd);
    void (*wakeup)(struct _PROCTHREAD *procthread);
    void (*stop)(struct _PROCTHREAD *procthread);
    void (*terminate)(struct _PROCTHREAD *procthread);
    void (*clean)(struct _PROCTHREAD *procthread);
}PROCTHREAD;
/* CONN */
typedef struct _CONN
{
    int index;
    int groupid;
    int gindex;
    int xindex;
    int s_id;
    int s_state;
    int timeout;
    int evstate;
    int status;
    int i_state;
    int c_state;
    int e_state;
    int c_id;
    int d_state;
    int evid;
    int qid;
    int nqleft;
    int qblock_max;
    int  sock_type;
    int  fd;
    int  remote_port;
    int  local_port;
    int  nsendq;
    int  flags;
    /* xid */
    int xids[SB_XIDS_MAX];
    EVENT event;
    EVENT outevent;
    /* buffer */
    MMBLOCK buffer;
    MMBLOCK packet;
    MMBLOCK cache;
    MMBLOCK header;
    MMBLOCK oob;
    MMBLOCK exchange;
    CHUNK chunk;
    CHUNK chunk2;
    QBLOCK xblock;
    QBLOCK qblocks[SB_QBLOCK_MAX];
    QBLOCK *qleft[SB_QBLOCK_MAX];
    QBLOCK *qhead;
    QBLOCK *qtail;
    /* evbase */
    void *mutex;
    EVBASE *evbase;
    EVBASE *outevbase;
    void *parent;
    void *queue;
    void *service;
    //void *xqueue;
    /* SSL */
    void *ssl;
    /* evtimer */
    void *evtimer;
    /* logger and timer */
    void *logger;
    /* message queue */
    void *indaemon;
    void *outdaemon;
    void *inqmessage;
    void *outqmessage;
    void *message_queue;
    int (*set)(struct _CONN *);
    int (*close)(struct _CONN *);
    int (*over)(struct _CONN *);
    int (*terminate)(struct _CONN *);

    /* client transaction state */
    int (*start_cstate)(struct _CONN *);
    int (*over_cstate)(struct _CONN *);
    /* error state */
    int (*wait_estate)(struct _CONN *);
    int (*over_estate)(struct _CONN *);
    
    /* event state */
#define EVSTATE_INIT   0
#define EVSTATE_WAIT   1 
    int (*wait_evtimeout)(struct _CONN *, int timeout_usec);
    int (*wait_evstate)(struct _CONN *);
    int (*over_evstate)(struct _CONN *);

    /* timeout */
    int (*set_timeout)(struct _CONN *, int timeout_usec);
    int (*timeout_handler)(struct _CONN *);
    int (*over_timeout)(struct _CONN *);
  
    /* message */
    int (*push_message)(struct _CONN *, int message_id);

    /* session */
    void (*outevent_handler)(struct _CONN *);
    int (*read_handler)(struct _CONN *);
    int (*write_handler)(struct _CONN *);
    int (*send_handler)(struct _CONN *);
    int (*packet_reader)(struct _CONN *);
    int (*packet_handler)(struct _CONN *);
    int (*oob_handler)(struct _CONN *);
    int (*okconn_handler)(struct _CONN *);
    int (*chunk_handler)(struct _CONN *);
    int (*data_handler)(struct _CONN *);
    int (*bind_proxy)(struct _CONN *, struct _CONN *);
    int (*proxy_handler)(struct _CONN *);
    int (*close_proxy)(struct _CONN *);
    int (*push_exchange)(struct _CONN *, void *data, int size);
    int (*transaction_handler)(struct _CONN *, int );
    int (*save_cache)(struct _CONN *, void *data, int size);
    int (*save_header)(struct _CONN *, void *data, int size);

    /* chunk */
    int (*chunk_reader)(struct _CONN *);
    int (*chunk_reading)(struct _CONN *);
    int (*read_chunk)(struct _CONN *);
    int (*recv_chunk)(struct _CONN *, int size);
    int (*recv2_chunk)(struct _CONN *, int size, char *data, int ndata);
    int (*store_chunk)(struct _CONN *, char *data, int ndata);
    int (*recv_file)(struct _CONN *, char *file, long long offset, long long size);
    int (*push_chunk)(struct _CONN *, void *data, int size);
    int (*push_file)(struct _CONN *, char *file, long long offset, long long size);
    int (*send_chunk)(struct _CONN *, CB_DATA *chunk, int len);
    int (*relay_chunk)(struct _CONN *, char *data, int ndata);
    int (*over_chunk)(struct _CONN *);
    CB_DATA* (*newchunk)(struct _CONN *, int size);
    CB_DATA* (*mnewchunk)(struct _CONN *, int size);
    void (*freechunk)(struct _CONN *, CB_DATA *chunk);
    void (*setto_chunk2)(struct _CONN *);
    void (*reset_chunk2)(struct _CONN *);
    void(*buffer_handler)(struct _CONN *);
    void(*chunkio_handler)(struct _CONN *);
    void(*free_handler)(struct _CONN *);
    void(*end_handler)(struct _CONN *);
    void(*shut_handler)(struct _CONN *);
    void(*shutout_handler)(struct _CONN *);
    
    /* normal */
    void (*reset_xids)(struct _CONN *);
    void (*reset_state)(struct _CONN *);
    void (*reset)(struct _CONN *);
    void (*clean)(struct _CONN *conn);
    /* session option and callback  */
    int (*set_session)(struct _CONN *, SESSION *session);
    int (*over_session)(struct _CONN *);
    int (*newtask)(struct _CONN *, CALLBACK *);
    int (*add_multicast)(struct _CONN *, char *);
    int (*get_service_id)(struct _CONN *);
    char remote_ip[SB_IP_MAX];
    char local_ip[SB_IP_MAX];
    SESSION session;
    /* connection bytes stats */
    long long   recv_oob_total;
    long long   sent_oob_total;
    long long   recv_data_total;
    long long   sent_data_total;
    /* xid 64 bit */
    int64_t  xids64[SB_XIDS_MAX];
}CONN, *PCONN;
CONN *conn_init();
#ifdef __cplusplus
 }
#endif
#endif
