#include "sbase.h"
#include "xssl.h"
#include "conn.h"
#include "mmblock.h"
#include "chunk.h"
#include "logger.h"
#include "message.h"
#include "service.h"
#include "evtimer.h"
#include "xmm.h"
#ifndef PPL
#define PPL(_x_) ((void *)(_x_))
#endif
#ifndef LL
#define LL(_x_) ((long long int)(_x_))
#endif
int conn__push__message(CONN *conn, int message_id);
int conn_shut(CONN *conn, int d_state, int e_state);
int conn_reading_chunk(CONN *conn)
{
	if(conn->ssl) return CHUNK_READ_SSL(&conn->chunk, conn->ssl);
	else return CHUNK_READ(&conn->chunk, conn->fd);
}
/* reading chunk */
int conn_chunk_reading(CONN *conn)
{
    int ret = -1, n = 0;

    if(conn)
    {
        if(conn->session.chunk_reader == NULL)
        {
            WARN_LOGGER(conn->logger, "NO session.chunk_reader() on connection remote[%s:%d] local[%s:%d] via %d", conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
            return ret;
        }
        if((n = conn->session.chunk_reader(conn, PCB(conn->buffer))) > 0)
        {
            chunk_mem(&(conn->chunk), n);
            conn->s_state = S_STATE_READ_CHUNK;
            conn__read__chunk(conn);
            //conn->recv_chunk(conn, n);
            //conn->s_state = S_STATE_DATA_HANDLING;
            //conn_push_message(conn, MESSAGE_CHUNK);
            ret = 0;
        }
    }
    return ret;
}

int conn_write_chunk(CONN *conn, CHUNK *cp)
{
    if(conn->session.flags & SB_MULTICAST)
    {
        return CHUNK_SENDTO(cp, conn->fd, conn->remote_ip, conn->remote_port);
    }
	else if(conn->ssl) 
    {
        return CHUNK_WRITE_SSL(cp, conn->ssl);
    }
	else 
    {
        return CHUNK_WRITE(cp, conn->fd);
    }
    return -1;
}
int conn_read_buffer(CONN *conn)
{
	if(conn->ssl) return MMB_READ_SSL(conn->buffer, conn->ssl);
	else return MMB_READ(conn->buffer, conn->fd);
}
void conn_pushto_sendq(CONN *conn, CHUNK *cp)
{
    QBLOCK *qblock = NULL;

    if(conn && (qblock = (QBLOCK *)cp))
    {
        MUTEX_LOCK(conn->mutex);
        qblock->next = NULL;
        if(conn->qtail)
        {
            conn->qtail->next = qblock;
            conn->qtail = qblock;
        }
        else
        {
            conn->qhead = conn->qtail = qblock;
        }
        conn->nsendq++;
        MUTEX_UNLOCK(conn->mutex);
    }
    return ;
}

CHUNK *conn_sendq_head(CONN *conn)
{
    CHUNK *chunk = NULL;

    if(conn)
    {
        MUTEX_LOCK(conn->mutex);
        chunk = (CHUNK *)conn->qhead;
        MUTEX_UNLOCK(conn->mutex);
    }
    return chunk;
}

CHUNK *conn_popfrom_sendq(CONN *conn)
{
    CHUNK *chunk = NULL;

    if(conn)
    {
        MUTEX_LOCK(conn->mutex);
        if((chunk = (CHUNK *)conn->qhead)) 
        {
            if((conn->qhead = conn->qhead->next) == NULL)
                conn->qtail = NULL;
            conn->nsendq--;
        }
        MUTEX_UNLOCK(conn->mutex);
    }
    return chunk;
}

#define PPARENT(conn) ((PROCTHREAD *)(conn->parent))
#define INDAEMON(conn) ((PROCTHREAD *)(conn->indaemon))
#define INWAKEUP(conn) {if(INDAEMON(conn))INDAEMON(conn)->wakeup(INDAEMON(conn));}            
#define OUTDAEMON(conn) ((PROCTHREAD *)(conn->outdaemon))
#define OUTWAKEUP(conn) {if(OUTDAEMON(conn))OUTDAEMON(conn)->wakeup(OUTDAEMON(conn));}            
/*
#define SENDQ(conn) conn->xqueue
#define SENDQINIT(conn) do{}while(0) 
#define SENDQNEW(conn) conn->qid = xqueue_new(conn->xqueue)
#define SENDQTOTAL(conn) xqueue_total(conn->xqueue, conn->qid)
#define SENDQHEAD(conn) xqueue_head(conn->xqueue, conn->qid)
#define SENDQPOP(conn) xqueue_pop(conn->xqueue, conn->qid)
#define SENDQPUSH(conn, ptr) xqueue_push(conn->xqueue, conn->qid, ptr)
#define SENDQCLOSE(conn) xqueue_close(conn->xqueue, conn->qid)
#define SENDQCLEAN(conn) do{}while(0)
#define SENDQ(conn) conn->queue
#define SENDQINIT(conn) (conn->queue = queue_init())
#define SENDQNEW(conn) do{}while(0)
#define SENDQTOTAL(conn) queue_total(conn->queue)
#define SENDQHEAD(conn) queue_head(conn->queue)
#define SENDQPOP(conn) queue_pop(conn->queue)
#define SENDQPUSH(conn, ptr) queue_push(conn->queue, ptr)
#define SENDQCLOSE(conn) do{}while(0)
#define SENDQCLEAN(conn) (queue_clean(conn->queue))
*/
#define SENDQ(conn) (conn->qblocks)
#define SENDQTOTAL(conn) conn->nsendq
#define SENDQHEAD(conn) conn_sendq_head(conn)
#define SENDQPOP(conn) conn_popfrom_sendq(conn)
#define SENDQPUSH(conn, ptr) conn_pushto_sendq(conn, ptr)
#define SENDQCLOSE(conn) do{}while(0)
#define SENDQCLEAN(conn) 


#define CONN_CHECK_RET(conn, _state_, ret)                                                  \
{                                                                                           \
    if(conn == NULL ) return ret;                                                           \
    if(conn->d_state & (_state_)) return ret;                                               \
}
#define CONN_CHECK(conn, _state_)                                                           \
{                                                                                           \
    if(conn == NULL) return ;                                                               \
    if(conn->d_state & (_state_)) return ;                                                  \
}
#define CONN_OUTEVENT_ADD(conn)                                                             \
do                                                                                          \
{                                                                                           \
    if(conn)                                                                                \
    {                                                                                       \
        if(conn->outdaemon)                                                                 \
        {                                                                                   \
            if(!(conn->outevent.ev_flags & E_WRITE))event_add(&(conn->outevent), E_WRITE);  \
        }                                                                                   \
        else                                                                                \
        {                                                                                   \
            if(!(conn->event.ev_flags & E_WRITE))event_add(&(conn->event), E_WRITE);        \
        }                                                                                   \
    }                                                                                       \
}while(0)
#define CONN_OUTEVENT_DEL(conn)                                                             \
do                                                                                          \
{                                                                                           \
    if(conn)                                                                                \
    {                                                                                       \
        if(conn->outdaemon)                                                                 \
        {                                                                                   \
            if(conn->outevent.ev_flags & E_WRITE)event_del(&(conn->outevent), E_WRITE);     \
        }                                                                                   \
        else                                                                                \
        {                                                                                   \
            if(conn->event.ev_flags & E_WRITE)event_del(&(conn->event), E_WRITE);           \
        }                                                                                   \
    }                                                                                       \
}while(0)
#define CONN_OUTEVENT_DESTROY(conn)                                                         \
do                                                                                          \
{                                                                                           \
    if(conn)                                                                                \
    {                                                                                       \
        if(conn->outdaemon)                                                                 \
        {                                                                                   \
            event_destroy(&(conn->outevent));                                               \
        }                                                                                   \
        else                                                                                \
        {                                                                                   \
            event_destroy(&(conn->event));                                                  \
        }                                                                                   \
    }                                                                                       \
}while(0)

#define CONN_OUTEVENT_MESSAGE(conn)                                                         \
do{                                                                                         \
    if(conn)                                                                                \
    {                                                                                       \
        if(conn->outdaemon)                                                                 \
        {                                                                                   \
            qmessage_push(conn->outqmessage, MESSAGE_OUT,                                   \
                        conn->index, conn->fd, -1, conn->outdaemon, conn, NULL);            \
            OUTDAEMON(conn)->wakeup((OUTDAEMON(conn)));                                     \
        }                                                                                   \
        else if(conn->indaemon)                                                             \
        {                                                                                   \
            qmessage_push(conn->inqmessage, MESSAGE_OUT,                                    \
                        conn->index, conn->fd, -1, conn->indaemon, conn, NULL);             \
            INDAEMON(conn)->wakeup((INDAEMON(conn)));                                       \
        }                                                                                   \
        else                                                                                \
        {                                                                                   \
            event_add(&(conn->event), E_WRITE);                                             \
        }                                                                                   \
    }                                                                                       \
}while(0)

#define CONN_STATE_RESET(conn)                                                              \
{                                                                                           \
    if(conn)                                                                                \
    {                                                                                       \
        conn->s_state = 0;                                                                  \
    }                                                                                       \
}

#define CONN_CHUNK_READ(conn, n)                                                            \
do                                                                                          \
{                                                                                           \
    /* read to chunk */                                                                     \
    if(conn->s_state ==  S_STATE_READ_CHUNK)                                                \
    {                                                                                       \
        if((n = conn_reading_chunk(conn)) <= 0)                                             \
        {                                                                                   \
            WARN_LOGGER(conn->logger, "Reading %d bytes (recv:%lld sent:%lld) data from conn[%p][%s:%d] ssl:%p on %s:%d via %d failed, %s", n, LL(conn->recv_data_total), LL(conn->sent_data_total), conn, conn->remote_ip, conn->remote_port,  conn->ssl, conn->local_ip, conn->local_port, conn->fd, strerror(errno));    \
            break;                                                                          \
        }                                                                                   \
        ACCESS_LOGGER(conn->logger, "Read %d bytes ndata:%d left:%lld to chunk from %s:%d"   \
                " on %s:%d via %d", n, CHK_NDATA(conn->chunk), LL(CHK_LEFT(conn->chunk)),   \
                conn->remote_ip, conn->remote_port, conn->local_ip,                         \
                conn->local_port, conn->fd);                                                \
        if(CHUNK_STATUS(&conn->chunk) == CHUNK_STATUS_OVER )                                \
        {                                                                                   \
            ACCESS_LOGGER(conn->logger, "Chunk completed %lld bytes from %s:%d "             \
                    "on %s:%d via %d", LL(CHK_SIZE(conn->chunk)), conn->remote_ip,          \
                    conn->remote_port, conn->local_ip, conn->local_port, conn->fd);         \
            conn->s_state = S_STATE_DATA_HANDLING;                                          \
            conn_push_message(conn, MESSAGE_DATA);                                          \
        }                                                                                   \
    }                                                                                       \
}while(0)
/* evtimer setting */
#define CONN_EVTIMER_SET(conn)                                                              \
do                                                                                          \
{                                                                                           \
    if(conn && conn->evtimer && conn->timeout > 0)                                          \
    {                                                                                       \
        if(conn->evid >= 0)                                                                 \
        {                                                                                   \
            EVTIMER_UPDATE(conn->evtimer, conn->evid, conn->timeout,                        \
                    &conn_evtimer_handler, (void *)conn);                                   \
        }                                                                                   \
        else                                                                                \
        {                                                                                   \
            conn->evid = EVTIMER_ADD(conn->evtimer, conn->timeout,                          \
                    &conn_evtimer_handler, (void *)conn);                                   \
        }                                                                                   \
    }                                                                                       \
}while(0)

/* update evtimer */
#define CONN_UPDATE_EVTIMER(conn , _evtimer_, _evid_)                                       \
do                                                                                          \
{                                                                                           \
    if(conn && (_evtimer_ = conn->evtimer) && conn->d_state == 0 && conn->timeout > 0       \
            && (_evid_ = conn->evid) >= 0)                                                  \
    {                                                                                       \
        EVTIMER_UPDATE(_evtimer_, _evid_, conn->timeout,                                    \
                &conn_evtimer_handler, (void *)conn);                                       \
    }                                                                                       \
}while(0)

#define PUSH_INQMESSAGE(conn, msgid)                                                        \
do                                                                                          \
{                                                                                           \
    if(conn && conn->d_state == 0)                                                          \
    {                                                                                       \
        qmessage_push(conn->inqmessage, msgid,                                              \
                conn->index, conn->fd, -1, conn->indaemon, conn, NULL);                     \
        INWAKEUP(conn);                                                                     \
    }                                                                                       \
}while(0)
#define SESSION_RESET(conn)                                                                 \
do                                                                                          \
{                                                                                           \
    MMB_RESET(conn->packet);                                                                \
    MMB_RESET(conn->cache);                                                                 \
    chunk_reset(&(conn->chunk));                                                            \
    CONN_STATE_RESET(conn);                                                                 \
    if(MMB_NDATA(conn->buffer) > 0){PUSH_INQMESSAGE(conn, MESSAGE_BUFFER);}                 \
}while(0)

/* out event handler */
void conn_outevent_handler(CONN *conn)
{
    int ret = -1;

    if(conn)
    {
        if(SENDQTOTAL(conn) > 0)
        {
            if(PPARENT(conn) && PPARENT(conn)->service 
                    && (PPARENT(conn)->service->flag & SB_WHILE_SEND))
                ret = conn->send_handler(conn);
            else
                ret = conn->write_handler(conn);
            if(ret < 0)
            {
                CONN_OUTEVENT_DESTROY(conn);
                conn_shut(conn, D_STATE_CLOSE|D_STATE_RCLOSE|D_STATE_WCLOSE, E_STATE_ON);
            }
            else 
            {
                conn->sent_data_total += ret;
                if(SENDQTOTAL(conn) > 0)
                {
                    CONN_OUTEVENT_ADD(conn);
                }
            }
        }
    }
    return ;
}
/* read  packet from buffer  */
void conn_buffer_handler(CONN *conn)
{
    int ret = -1;
    CONN_CHECK(conn, D_STATE_CLOSE);

    if(conn)
    {
        if(conn->s_state == 0) ret = conn->packet_reader(conn);
    }
    return ;
}

/* write */
void conn_chunkio_handler(CONN *conn)
{
    CONN_CHECK(conn, D_STATE_CLOSE);
    int ret = -1;

    if(conn)
    {
        if(conn->s_state == S_STATE_CHUNK_READING)
        {
            ret =  conn_chunk_reading(conn);
            return ;
        }
        if(conn->s_state == S_STATE_READ_CHUNK) 
            ret = conn__read__chunk(conn);
    }
    return ;
}

/* over */
void conn_shutout_handler(CONN *conn)
{
    PROCTHREAD *daemon = NULL;

    if(conn)
    {
        if(conn->outdaemon) event_destroy(&(conn->outevent));
        if((daemon = (PROCTHREAD *)(conn->indaemon)))
        {
            DEBUG_LOGGER(conn->logger, "Ready for shut-connection[%s:%d] on inqmessage[%p] local[%s:%d] via %d ", conn->remote_ip, conn->remote_port, conn->inqmessage, conn->local_ip, conn->local_port, conn->fd);
            qmessage_push(conn->inqmessage, MESSAGE_OVER,
                    conn->index, conn->fd, -1, conn->indaemon, conn, NULL);
            daemon->wakeup(daemon);
        }
        else if((daemon = (PROCTHREAD *)(conn->parent)))
        {
            DEBUG_LOGGER(conn->logger, "Ready for quit-connection[%s:%d] local[%s:%d] via %d ", conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd)
            qmessage_push(conn->message_queue, MESSAGE_QUIT, 
                    conn->index, conn->fd, -1, conn->parent, conn, NULL);
            daemon->wakeup(daemon);
        }
    }
    return ;
}

/* shut */
void conn_shut_handler(CONN *conn)
{
    PROCTHREAD *daemon = NULL;

    if(conn)
    {
        if((daemon = (PROCTHREAD *)conn->outdaemon))
        {
            DEBUG_LOGGER(conn->logger, "Ready for shut-connection-out[%s:%d] local[%s:%d] via %d ", conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
            qmessage_push(conn->outqmessage, MESSAGE_SHUTOUT,
                    conn->index, conn->fd, -1, conn->outdaemon, conn, NULL);
            daemon->wakeup(daemon);
        }
        else if((daemon = (PROCTHREAD *)conn->indaemon))
        {
            DEBUG_LOGGER(conn->logger, "Ready for shut-connection[%s:%d] local[%s:%d] via %d ", conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
            qmessage_push(conn->inqmessage, MESSAGE_OVER,
                    conn->index, conn->fd, -1, conn->indaemon, conn, NULL);
            daemon->wakeup(daemon);
        }
        else if((daemon = (PROCTHREAD *)conn->parent))
        {
            DEBUG_LOGGER(conn->logger, "Ready for quit-connection[%s:%d] local[%s:%d] via %d ", conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd)
            qmessage_push(conn->message_queue, MESSAGE_QUIT, 
                    conn->index, conn->fd, -1, conn->parent, conn, NULL);
            daemon->wakeup(daemon);
        }
    }
    return ;
}

/* end handler  */
void conn_end_handler(CONN *conn)
{
    CONN_CHECK(conn, D_STATE_CLOSE);
    int n = 0;

    if(conn)
    {
        if((n = SENDQTOTAL(conn)) > 0) 
        {
            CONN_OUTEVENT_MESSAGE(conn);
        }
        //ACCESS_LOGGER(conn->logger, "end_handler conn[%p]->event{ev_flags:%d old_ev_flags:%d evbase:%p} qtotal:%d/%d nbufer:%d remote[%s:%d] local[%s:%d] via %d", conn, conn->event.ev_flags, conn->event.old_ev_flags, conn->event.ev_base, SENDQTOTAL(conn), n, MMB_NDATA(conn->buffer), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        if(conn->s_state == 0 && MMB_NDATA(conn->buffer) > 0){PUSH_INQMESSAGE(conn, MESSAGE_BUFFER);}
        //DEBUG_LOGGER(conn->logger, "end_handler conn[%p]->event{ev_flags:%d old_ev_flags:%d evbase:%p} qtotal:%d nbufer:%d remote[%s:%d] local[%s:%d] via %d", conn, conn->event.ev_flags, conn->event.old_ev_flags, conn->event.ev_base, SENDQTOTAL(conn), MMB_NDATA(conn->buffer), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
    }
    return ;
}

/* free handler  */
void conn_free_handler(CONN *conn)
{
    CONN_CHECK(conn, D_STATE_CLOSE);

    if(conn)
    {
        SESSION_RESET(conn);
        if(conn->session.flags & SB_MULTICAST) 
            PPARENT(conn)->service->freeconn(PPARENT(conn)->service, conn);
    }
    return ;
}

void conn_output_handler(int event_fd, int event, void *arg)
{
    CONN *conn = (CONN *)arg;
    int ret = -1;
    //void *evtimer = NULL;int evid = -1;

    if(conn)
    {
        if(event & E_READ)
        {
            CONN_OUTEVENT_DESTROY(conn);
            conn_shut(conn, D_STATE_CLOSE|D_STATE_RCLOSE|D_STATE_WCLOSE, E_STATE_ON);
            return ;
        }
        if(event & E_WRITE)
        {
            if(PPARENT(conn) && PPARENT(conn)->service 
                    && (PPARENT(conn)->service->flag & SB_WHILE_SEND))
                ret = conn->send_handler(conn);
            else
                ret = conn->write_handler(conn);
            if(ret < 0)
            {
                CONN_OUTEVENT_DESTROY(conn);
                conn_shut(conn, D_STATE_CLOSE|D_STATE_RCLOSE|D_STATE_WCLOSE, E_STATE_ON);
                return ;
            }
            else
            {
                conn->sent_data_total += ret;
            }
            //CONN_UPDATE_EVTIMER(conn, evtimer, evid);
        }
    }
    return ;
}

/* connection event handler */
void conn_event_handler(int event_fd, int event, void *arg)
{
    int len = sizeof(int), error = 0, ret = -1;
    CONN *conn = (CONN *)arg;
    //void *evtimer = NULL;int evid = -1;

    if(conn)
    {
        if(PPARENT(conn) && PPARENT(conn)->service && (PPARENT(conn)->service->flag & SB_LOG_THREAD))
        {
            WARN_LOGGER(conn->logger, "socket %d/%d to conn[%p]->event:{ev_flags:%d,old_ev_flags:%d evbase:%p} remote[%s:%d] local[%s:%d] event:%d", conn->fd, event_fd, conn, conn->event.ev_flags, conn->event.old_ev_flags, conn->event.ev_base, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, event);
        }
        if(event_fd == conn->fd)
        {
            //fprintf(stdout, "%s::%d event[%d] on fd[%d]\n", __FILE__, __LINE__, event, event_fd);
            if(conn->status == CONN_STATUS_READY)
            {
                ret = getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&len);
                if(ret < 0 || error != 0)
                {
                    WARN_LOGGER(conn->logger, "socket %d to conn[%p] remote[%s:%d] local[%s:%d] connectting failed, error:[%d]{%s}", conn->fd, conn, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, error, strerror(error));
                    CONN_OUTEVENT_DESTROY(conn);
                    conn_shut(conn, D_STATE_CLOSE, E_STATE_ON);          
                    return ;
                }
                DEBUG_LOGGER(conn->logger, "Connection[%s:%d] group[%d] local[%s:%d] via %d is OK event[%d]", conn->remote_ip, conn->remote_port, conn->groupid, conn->local_ip, conn->local_port, conn->fd, event);
                //set conn->status
                if(PPARENT(conn) && PPARENT(conn)->service)
                    PPARENT(conn)->service->okconn(PPARENT(conn)->service, conn);
                event_del(&(conn->event), E_WRITE);
                conn_push_message(conn, MESSAGE_OKCONN);
                return ;
            }
            if(conn->ssl) 
            {
                int flag = fcntl(conn->fd, F_GETFL, 0);
                if(flag & O_NONBLOCK)
                {
                    flag &= ~O_NONBLOCK;
                    fcntl(conn->fd, F_SETFL, flag);
                }
            }
            if(event & E_READ)
            {
                ret = conn->read_handler(conn);
                if(ret < 0)
                {
                    event_destroy(&(conn->event)); 
                    conn_shut(conn, D_STATE_CLOSE|D_STATE_RCLOSE|D_STATE_WCLOSE, E_STATE_ON);
                    return ;
                }
            }
            if((event & E_WRITE))
            {
                if(conn->outdaemon == NULL)
                {
                    if(PPARENT(conn) && PPARENT(conn)->service && (PPARENT(conn)->service->flag & SB_WHILE_SEND))
                        ret = conn->send_handler(conn);
                    else
                        ret = conn->write_handler(conn);
                    if(ret < 0)
                    {
                        event_destroy(&(conn->event)); 
                        conn_shut(conn, D_STATE_CLOSE|D_STATE_RCLOSE|D_STATE_WCLOSE, E_STATE_ON);
                        return ;
                    }
                }
                else
                {
                    event_destroy(&(conn->event)); 
                    conn_shut(conn, D_STATE_CLOSE|D_STATE_RCLOSE|D_STATE_WCLOSE, E_STATE_ON);
                    return ;
                }
            } 
            //CONN_UPDATE_EVTIMER(conn, evtimer, evid);
        }
        else
        {
            FATAL_LOGGER(conn->logger, "Invalid fd[%d:%d] event:%d", event_fd, conn->fd, event);
        }
    }
    return ;
}

/* set connection */
int conn_set(CONN *conn)
{
    int flag = 0;
    if(conn && conn->fd > 0 )
    {
        //non-block
        fcntl(conn->fd, F_SETFL, fcntl(conn->fd, F_GETFL, 0)|O_NONBLOCK);
        //timeout
        conn->evid = -1;
        if(conn->parent && conn->session.timeout > 0) conn->set_timeout(conn, conn->session.timeout);
        //SENDQNEW(conn);
        if(conn->outdaemon)
        {
            flag = E_PERSIST;
            if(PPARENT(conn)->service && (PPARENT(conn)->service->flag & SB_EVENT_LOCK))
                flag |= E_LOCK;
            event_set(&(conn->outevent), conn->fd, flag, (void *)conn, &conn_output_handler);
            conn->outevbase->add(conn->outevbase, &(conn->outevent));
        }
        if(conn->evbase)
        {
            flag = E_READ|E_PERSIST;
            if(PPARENT(conn)->service && (PPARENT(conn)->service->flag & SB_EVENT_LOCK))
                flag |= E_LOCK;
            if(conn->status == CONN_STATUS_READY) flag |= E_WRITE;
            event_set(&(conn->event), conn->fd, flag, (void *)conn, &conn_event_handler);
            DEBUG_LOGGER(conn->logger, "setting conn[%p]->evbase[%p] remote[%s:%d] d_state:%d local[%s:%d] via %d", conn, conn->evbase, conn->remote_ip, conn->remote_port, conn->d_state, conn->local_ip, conn->local_port, conn->fd);
            conn->evbase->add(conn->evbase, &(conn->event));

            return 0;
        }
        else
        {
            FATAL_LOGGER(conn->logger, "Connection[%p] fd[%d] evbase or initialize event failed, %s", conn, conn->fd, strerror(errno));	
            //conn_shut(conn, D_STATE_CLOSE, E_STATE_ON);
        }
    }	
    return -1;	
}

/* get service id */
int conn_get_service_id(CONN *conn)
{
    if(conn && conn->parent)
    {
        return PPARENT(conn)->service->id;
    }
    return -1;
}

/* close connection */
int conn_close(CONN *conn)
{
    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);

    if(conn)
    {
        DEBUG_LOGGER(conn->logger, "Ready for close-conn[%p] remote[%s:%d] local[%s:%d] via %d", conn, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        conn_shut(conn, D_STATE_CLOSE, E_STATE_OFF);
        return 0;
    }
    return -1;
}


/* over connection */
int conn_over(CONN *conn)
{
    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);
    int over = 0;

    if(conn)
    {
        DEBUG_LOGGER(conn->logger, "Ready for over-connection[%p] remote[%s:%d] local[%s:%d] via %d", conn, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        MUTEX_LOCK(conn->mutex);
        conn->over_timeout(conn);
        if(conn->d_state == D_STATE_FREE) over = 1;
        MUTEX_UNLOCK(conn->mutex);
        if(over)conn_over_chunk(conn);
        return 0;
    }
    return -1;
}

/* shutdown connection */
int conn_shut(CONN *conn, int d_state, int e_state)
{
    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);

    if(conn)
    {
        MUTEX_LOCK(conn->mutex);
        conn->over_timeout(conn);
        if(conn->d_state == D_STATE_FREE && conn->fd > 0)
        {
            conn->d_state |= d_state;
            if(conn->e_state == E_STATE_OFF) conn->e_state = e_state;
            conn__push__message(conn, MESSAGE_SHUT);
        }
        MUTEX_UNLOCK(conn->mutex);
    }
    return 0;
}

/* terminate connection */
int conn_terminate(CONN *conn)
{
    PROCTHREAD *parent = NULL;
    CHUNK *cp = NULL;
    int ret = -1;

    if(conn)
    {
        parent = (PROCTHREAD *)conn->parent;
        DEBUG_LOGGER(conn->logger, "Ready for terminate-conn[%p] remote[%s:%d] local[%s:%d] via %d qtotal:%d d_state:%d i_state:%d c_state:%d s_state:%d e_state:%d", conn, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, SENDQTOTAL(conn), conn->d_state, conn->i_state, conn->c_state, conn->s_state, conn->e_state);
        conn->d_state = D_STATE_CLOSE;
        //continue incompleted data handling 
        if(conn->s_state == S_STATE_DATA_HANDLING && CHK_NDATA(conn->chunk) > 0)
        {
            if(conn->session.packet_type == PACKET_PROXY)
            {
                conn->proxy_handler(conn);
            }
        }
        if((conn->s_state == S_STATE_CHUNK_READING) && MMB_NDATA(conn->buffer) > 0
                && conn->session.chunk_reader)
        {
            DEBUG_LOGGER(conn->logger, "chunk_reader() session[%s:%d] local[%s:%d] via %d cid:%d %d", conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, conn->c_id, conn->packet.ndata);
            if(conn->session.chunk_reader(conn, PCB(conn->buffer)) > 0)
            {
                DEBUG_LOGGER(conn->logger, "chunk_handler() session[%s:%d] local[%s:%d] via %d cid:%d %d", conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, conn->c_id, conn->packet.ndata);
                conn->session.chunk_handler(conn, PCB(conn->packet), PCB(conn->cache), PCB(conn->buffer));
                conn->e_state = E_STATE_OFF;
            }
        }
        if(conn->e_state == E_STATE_ON && conn->session.error_handler)
        {
            DEBUG_LOGGER(conn->logger, "error handler session[%s:%d] local[%s:%d] via %d cid:%d %d", conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, conn->c_id, conn->packet.ndata);
            conn->session.error_handler(conn, PCB(conn->packet), PCB(conn->cache), PCB(conn->chunk));
            MMB_RESET(conn->buffer); 
            MMB_RESET(conn->packet); 
            MMB_RESET(conn->cache); 
            MMB_RESET(conn->oob); 
            chunk_reset(&conn->chunk); 
        }
        conn->close_proxy(conn);
        EVTIMER_DEL(conn->evtimer, conn->evid);
        DEBUG_LOGGER(conn->logger, "terminateing conn[%p]->d_state:%d queue:%d session[%s:%d] local[%s:%d] via %d", conn, conn->d_state, SENDQTOTAL(conn), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        /* clean send queue */
        while((cp = (CHUNK *)SENDQPOP(conn)))
        {
            conn_freechunk(conn, (CB_DATA *)cp);
            cp = NULL;
        }
        DEBUG_LOGGER(conn->logger, "over-terminateing conn[%p]->d_state:%d queue:%d session[%s:%d] local[%s:%d] via %d", conn, conn->d_state, SENDQTOTAL(conn), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        /* SSL */
#ifdef HAVE_SSL
        if(conn->ssl)
        {
            SSL_shutdown(XSSL(conn->ssl));
            SSL_free(XSSL(conn->ssl));
            conn->ssl = NULL;
        }
#endif
        if(conn->fd > 0)
        {
            shutdown(conn->fd, SHUT_RDWR);
            close(conn->fd);
        }
        conn->fd = -1;
        ret = 0;
    }
    return ret;
}

void conn_evtimer_handler(void *arg)
{
    CONN *conn = (CONN *)arg;

    CONN_CHECK(conn, D_STATE_CLOSE);

    if(conn)
    {
        DEBUG_LOGGER(conn->logger, "evtimer_handler[%d](%p) on remote[%s:%d] local[%s:%d] via %d", conn->evid, PPL(conn->evtimer), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        conn_push_message(conn, MESSAGE_TIMEOUT);
    }
    return ;
}

/* set timeout */
int conn_set_timeout(CONN *conn, int timeout_usec)
{
    int ret = -1;

    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);

    if(conn && timeout_usec > 0)
    {
        conn->timeout = timeout_usec;
        CONN_EVTIMER_SET(conn);
        DEBUG_LOGGER(conn->logger, "set evtimer[%p] timeout[%d] evid:%d  s_state:%d on %s:%d local[%s:%d] via %d", PPL(conn->evtimer), conn->timeout, conn->evid, conn->s_state, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
    }
    return ret;
}

/* over timeout */
int conn_over_timeout(CONN *conn)
{
    int ret = -1;
    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);

    if(conn)
    {
        if(conn->evtimer && conn->timeout > 0 && conn->evid >= 0)
        {
            EVTIMER_DEL(conn->evtimer, conn->evid);
        }
        conn->timeout = 0;
        conn->evid = -1;
        ret = 0;
    }
    return ret;
}

/* set evstate as wait*/
int conn_wait_evstate(CONN *conn)
{
    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);
    if(conn)
    {
        conn->evstate = EVSTATE_WAIT;
        return 0;
    }
    return -1;
}

/* over evstate */
int conn_over_evstate(CONN *conn)
{
    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);
    if(conn)
    {
        conn->evstate = EVSTATE_INIT;
        return 0;
    }
    return -1;
}

/* set timeout */
int conn_wait_evtimeout(CONN *conn, int timeout_usec)
{
    int ret = -1;

    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);

    if(conn && timeout_usec > 0)
    {
        conn->evstate = EVSTATE_WAIT;
        conn->timeout = timeout_usec;
        CONN_EVTIMER_SET(conn);
        DEBUG_LOGGER(conn->logger, "set evtimer[%p] etimeout[%d] evid:%d  s_state:%d on %s:%d local[%s:%d] via %d", PPL(conn->evtimer), conn->timeout, conn->evid, conn->s_state, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
    }
    return ret;
}

/* timeout handler */
int conn_timeout_handler(CONN *conn)
{
    int ret = -1;

    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);

    if(conn && conn->evid >= 0)
    {
        if(conn->evstate == EVSTATE_WAIT && conn->session.evtimeout_handler)
        {
            DEBUG_LOGGER(conn->logger, "evtimeout_handler(%d) on remote[%s:%d] local[%s:%d] via %d", conn->timeout, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
            conn->evstate = EVSTATE_INIT;
            conn_over_timeout(conn);
            ret = conn->session.evtimeout_handler(conn);
            DEBUG_LOGGER(conn->logger, "over evtimeout_handler(%d) on remote[%s:%d] local[%s:%d] via %d", conn->timeout, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
            return ret;
        }
        if(conn->session.timeout_handler)
        {
            DEBUG_LOGGER(conn->logger, "timeout_handler(%d) on remote[%s:%d] local[%s:%d] via %d", conn->timeout, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
            CONN_STATE_RESET(conn);
            ret = conn->session.timeout_handler(conn, PCB(conn->packet), 
                    PCB(conn->cache), PCB(conn->chunk));
            DEBUG_LOGGER(conn->logger, "over timeout_handler(%d) on remote[%s:%d] local[%s:%d] via %d", conn->timeout, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
            return 0;
        }
        else
        {
            DEBUG_LOGGER(conn->logger, "TIMEOUT[%d]-close connection[%p] on remote[%s:%d] local[%s:%d] via %d", conn->timeout, conn, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
            conn_shut(conn, D_STATE_CLOSE, E_STATE_OFF);
        }
    }
    return -1;
}

/* start client transaction state */
int conn_start_cstate(CONN *conn)
{
    CHUNK *cp = NULL;
    int ret = -1;
    /* Check connection and transaction state */
    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);

    if(conn)
    {
        if(conn->c_state == C_STATE_FREE)
        {
            DEBUG_LOGGER(conn->logger, "Start cstate on conn[%s:%d] local[%s:%d] via %d ", conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
            conn->c_state = C_STATE_USING;
            while((cp = (CHUNK *)SENDQPOP(conn)))
            {
                conn_freechunk(conn, (CB_DATA *)cp);
                cp  = NULL;
            }
            MMB_RESET(conn->packet);
            MMB_RESET(conn->cache);
            MMB_RESET(conn->buffer);
            MMB_RESET(conn->oob);
            MMB_RESET(conn->exchange);
            chunk_reset(&conn->chunk);
            ret = 0;
        }
    }
    return ret;
}

/* start error wait state */
int conn_wait_estate(CONN *conn)
{
    int ret = -1;
    /* Check connection and transaction state */
    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);

    if(conn)
    {
        if(conn->e_state == E_STATE_OFF)
        {
            conn->e_state = E_STATE_ON;
            ret = 0;
        }
    }
    return ret;
}

/* over error wait state */
int conn_over_estate(CONN *conn)
{
    int ret = -1;
    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);

    if(conn)
    {
        conn->e_state = E_STATE_OFF;
        ret = 0;
    }
    return ret;
}

/* over client transaction state */
int conn_over_cstate(CONN *conn)
{
    int ret = -1;
    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);

    if(conn)
    {
        conn->c_state = C_STATE_FREE;
        EVTIMER_DEL(conn->evtimer, conn->evid);
        ret = 0;
    }
    return ret;
}

/* push message to message queue */
int conn__push__message(CONN *conn, int message_id)
{
    PROCTHREAD *parent = NULL;
    int ret = -1;

    if(conn && conn->message_queue && message_id > 0 && (message_id <= MESSAGE_MAX) )
    {
        if((parent = (PROCTHREAD *)conn->parent))
        {
            DEBUG_LOGGER(conn->logger, "Ready for pushing message[%s] to inqmessage[%p] on conn[%s:%d] local[%s:%d] via %d total %d handler[%p] parent[%p]", messagelist[message_id], PPL(conn->message_queue), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, QMTOTAL(conn->message_queue), PPL(conn), parent);
            qmessage_push(conn->message_queue, message_id, conn->index, conn->fd, -1, parent, conn, NULL);
            parent->wakeup(parent);
        }
        ret = 0;
    }
    return ret;
}

/* push message to message queue */
int conn_push_message(CONN *conn, int message_id)
{
    PROCTHREAD *parent = NULL;
    int ret = -1;

    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);

    if(conn && conn->message_queue && message_id > 0 && message_id <= MESSAGE_MAX )
    {
        if((parent = (PROCTHREAD *)conn->parent))
        {
            qmessage_push(conn->message_queue, message_id, conn->index, conn->fd, 
                    -1, parent, conn, NULL);
            parent->wakeup(parent);
            ret = 0;
        }
    }
    return ret;
}

/* read handler */
int conn_read_handler(CONN *conn)
{
    int ret = -1, n = -1;

    CONN_CHECK_RET(conn, (D_STATE_RCLOSE|D_STATE_CLOSE), ret);

    if(conn)
    {
        if((conn->session.flags & SB_USE_OOB) && (n = MMB_RECV(conn->oob, conn->fd, MSG_OOB)) > 0)
        {
            conn->recv_oob_total += n;
            DEBUG_LOGGER(conn->logger, "Received %d bytes OOB total %lld from %s:%d on %s:%d via %d", n, LL(conn->recv_oob_total), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
            if((n = conn->oob_handler(conn)) > 0)
            {
                MMB_DELETE(conn->oob, n);
            }
            // CONN TIMER sample 
            return (ret = 0);
        }
        /* Receive to chunk with chunk_read_state before reading to buffer */
        if(conn->s_state == S_STATE_READ_CHUNK
                && conn->session.packet_type != PACKET_PROXY
                && CHK_LEFT(conn->chunk) > 0)
        {
            if(conn->buffer.ndata > 0) ret = conn__read__chunk(conn);
            if(conn->buffer.ndata <= 0){CONN_CHUNK_READ(conn, n);ret = n;if(n == 0) ret = -1;}
            return ret;
            //goto end;
        }
        /* Receive normal data */
        if(conn->ssl) 
        {
            n = MMB_READ_SSL(conn->buffer, conn->ssl);
        }
	    else 
        {
            n = MMB_READ(conn->buffer, conn->fd);
        }
        if(n < 1)
        {
            WARN_LOGGER(conn->logger, "Reading data %d bytes (recv:%lld sent:%lld) ptr:%p buffer-left:%d qleft:%d from %s:%d on %s:%d via %d failed, %s", n, LL(conn->recv_data_total), LL(conn->sent_data_total), MMB_END(conn->buffer), MMB_LEFT(conn->buffer), SENDQTOTAL(conn), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, strerror(errno));
            return ret;
        }
        else
        {
            conn->recv_data_total += n;
        }
        ACCESS_LOGGER(conn->logger, "Received %d bytes s_state:%d npacket:%d nbuffer:%d/%d  left:%d data total %lld from %s:%d on %s:%d via %d", n, conn->s_state, conn->packet.ndata, conn->buffer.ndata, MMB_SIZE(conn->buffer), MMB_LEFT(conn->buffer), LL(conn->recv_data_total), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        if(conn->session.packet_type & PACKET_PROXY)
        {
            ret = conn->proxy_handler(conn);
            if(conn->session.packet_type == PACKET_PROXY) return ret;
        }
        if(conn->s_state == 0 && conn->packet.ndata == 0)
            ret = conn->packet_reader(conn);
        /* reading chunk */
        if(conn->s_state == S_STATE_CHUNK_READING) 
            ret = conn_chunk_reading(conn);
        ret = 0;
    }
    return ret;
}

/* write handler */
int conn_write_handler(CONN *conn)
{
    int ret = -1, n = 0, chunk_over = 0, nsent = 0;
    CHUNK *cp = NULL;
    CONN_CHECK_RET(conn, (D_STATE_CLOSE|D_STATE_WCLOSE), ret);

    if(conn)
    {
        if(SENDQTOTAL(conn) > 0)
        {
            if((cp = (CHUNK *)SENDQHEAD(conn)))
            {
                chunk_over = 0;
                if(CHUNK_STATUS(cp) != CHUNK_STATUS_OVER)
                {
                    if((n = conn_write_chunk(conn, cp)) > 0)
                    {
                        conn->sent_data_total += n;
                        nsent += n;
                        ACCESS_LOGGER(conn->logger, "Sent %d byte(s) (total sent %lld) to %s:%d on %s:%d via %d leave %lld qtotal:%d", n, LL(conn->sent_data_total), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, LL(CHK(cp)->left), SENDQTOTAL(conn));
                        ret = n;
                    }
                    else
                    {
                        if(errno != EINTR && errno != EAGAIN)
                        {
                            WARN_LOGGER(conn->logger, "write %d byte(s) (total sent %lld) to %s:%d on %s:%d via %d leave %lld qtotal:%d failed, %s", n, LL(conn->sent_data_total), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, LL(CHK(cp)->left), SENDQTOTAL(conn), strerror(errno));
#ifdef HAVE_SSL
                            if(conn->ssl) ERR_print_errors_fp(stdout);
#endif
                            return (ret = -1);
                        }
                        ret = 0;
                    }
                }
                else
                {
                    chunk_over = 1;
                    ret = 0;
                }
                /* CONN TIMER sample */
                if(CHUNK_STATUS(cp) == CHUNK_STATUS_OVER)
                {
                    if((cp = (CHUNK *)SENDQPOP(conn)))
                    {
                        DEBUG_LOGGER(conn->logger, "Completed chunk[%p] to %s:%d on %s:%d via %d clean it leave %d", PPL(cp), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, SENDQTOTAL(conn));
                        conn_freechunk(conn, (CB_DATA *)cp);
                        cp  = NULL;
                    }
                }
                if((cp = (CHUNK *)SENDQHEAD(conn)) && CHUNK_STATUS(cp) == CHUNK_STATUS_OVER)
                {
                    chunk_over = 1;
                    if((cp = (CHUNK *)SENDQPOP(conn))) conn_freechunk(conn, (CB_DATA *)cp);
                }
                if(chunk_over)
                {
                    CONN_OUTEVENT_DEL(conn);
                    if(conn->session.flags & SB_MULTICAST)
                    {
                        conn_push_message(conn, MESSAGE_FREE);
                    }
                    else
                    {
                        conn_shut(conn, D_STATE_CLOSE, E_STATE_OFF);
                    }
                }
                else
                {
                    if(SENDQTOTAL(conn) < 1) 
                    {
                        CONN_OUTEVENT_DEL(conn);
                        conn_push_message(conn, MESSAGE_END);
                    }
                }
            }
            ACCESS_LOGGER(conn->logger, "Over for send-ndata[%d] to %s:%d on %s:%d via %d qtotal:%d d_state:%d i_state:%d", nsent, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, SENDQTOTAL(conn), conn->d_state, conn->i_state);
        }
        else
        {
            CONN_OUTEVENT_DEL(conn);
            ACCESS_LOGGER(conn->logger, "nodata to %s:%d on %s:%d via %d qtotal:%d d_state:%d i_state:%d", conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, SENDQTOTAL(conn), conn->d_state, conn->i_state);
            ret = 0;
        }
    }
    return ret;
}

/* write handler */
int conn_send_handler(CONN *conn)
{
    int ret = -1, n = 0, chunk_over = 0, nsent = 0;
    CHUNK *cp = NULL;
    CONN_CHECK_RET(conn, (D_STATE_CLOSE|D_STATE_WCLOSE), ret);

    if(conn)
    {
        if(SENDQTOTAL(conn) > 0)
        {
            while(SENDQTOTAL(conn) > 0 && (cp = (CHUNK *)SENDQHEAD(conn)))
            {
                chunk_over = 0;
                if(CHUNK_STATUS(cp) != CHUNK_STATUS_OVER)
                {
                    if((n = conn_write_chunk(conn, cp)) > 0)
                    {
                        conn->sent_data_total += n;
                        nsent += n;
                        ACCESS_LOGGER(conn->logger, "Sent %d byte(s) (total sent %lld) to %s:%d on %s:%d via %d leave %lld qtotal:%d", n, LL(conn->sent_data_total), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, LL(CHK(cp)->left), SENDQTOTAL(conn));
                        ret = nsent;
                    }
                    else
                    {
                        if(errno != EINTR && errno != EAGAIN)
                        {
                            WARN_LOGGER(conn->logger, "write %d byte(s) (recv:%lld sent:%lld) to %s:%d on %s:%d via %d leave %lld qtotal:%d failed, %s", n, LL(conn->recv_data_total), LL(conn->sent_data_total), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, LL(CHK(cp)->left), SENDQTOTAL(conn), strerror(errno));
#ifdef HAVE_SSL
                            if(conn->ssl) ERR_print_errors_fp(stdout);
#endif
                            ret = -1;break;
                        }
                        ret = 0;break;
                    }
                }
                else
                {
                    chunk_over = 1;
                    ret = 0;
                }
                /* CONN TIMER sample */
                if(CHUNK_STATUS(cp) == CHUNK_STATUS_OVER)
                {
                    if((cp = (CHUNK *)SENDQPOP(conn)))
                    {
                        ACCESS_LOGGER(conn->logger, "Completed chunk[%p] to %s:%d on %s:%d via %d clean it leave %d", PPL(cp), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, SENDQTOTAL(conn));
                        conn_freechunk(conn, (CB_DATA *)cp);
                        cp  = NULL;
                    }
                }
                else 
                {
                    break; 
                }
                if(chunk_over)
                {
                    CONN_OUTEVENT_DEL(conn);
                    if(conn->session.flags & SB_MULTICAST)
                    {
                        conn_push_message(conn, MESSAGE_FREE);
                    }
                    else
                    {
                        conn_shut(conn, D_STATE_CLOSE, E_STATE_OFF);
                    }
                    ret = 0;break;
                }
                else
                {
                    if(SENDQTOTAL(conn) < 1) 
                    {
                        CONN_OUTEVENT_DEL(conn);
                        conn_push_message(conn, MESSAGE_END);
                    }
                    ret = 0; break;
                }
            }
            ACCESS_LOGGER(conn->logger, "Over for send-ndata[%d] to %s:%d on %s:%d via %d qtotal:%d d_state:%d i_state:%d", nsent, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, SENDQTOTAL(conn), conn->d_state, conn->i_state);
        }
        else
        {
            ret = 0;
            CONN_OUTEVENT_DEL(conn);
            ACCESS_LOGGER(conn->logger, "nodata to %s:%d on %s:%d via %d qtotal:%d d_state:%d i_state:%d", conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, SENDQTOTAL(conn), conn->d_state, conn->i_state);
        }
    }
    return ret;
}

/* packet reader */
int conn_packet_reader(CONN *conn)
{
    int packet_type = 0, len = -1, n = 0;
    char *p = NULL, *e = NULL;
    CB_DATA *data = NULL;

    CONN_CHECK_RET(conn, (D_STATE_CLOSE), -1);

    if(conn && conn->s_state == 0)
    {
        data = PCB(conn->buffer);
        e = MMB_END(conn->buffer);
        packet_type = conn->session.packet_type;

        /* Remove invalid packet type */
        if(!(packet_type & PACKET_ALL))
        {
            WARN_LOGGER(conn->logger, "Unkown packet_type[%d] from %s:%d on conn[%p] %s:%d via %d", packet_type, conn->remote_ip, conn->remote_port, conn, conn->local_ip, conn->local_port, conn->fd);
            /* Terminate connection */
            conn_shut(conn, D_STATE_CLOSE, E_STATE_ON);
        }
        /* Read packet with customized function from user */
        else if(packet_type & PACKET_CUSTOMIZED && conn->session.packet_reader)
        {
            len = conn->session.packet_reader(conn, data);
            ACCESS_LOGGER(conn->logger, "Reading packet with customized function[%p] length[%d]-[%d] from %s:%d on %s:%d via %d", PPL(conn->session.packet_reader), len, data->ndata, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
            goto end;
        }
        /* Read packet with certain length */
        else if(packet_type & PACKET_CERTAIN_LENGTH
                && MMB_NDATA(conn->buffer) >= conn->session.packet_length)
        {
            len = conn->session.packet_length;
            ACCESS_LOGGER(conn->logger, "Reading packet with certain length[%d] from %s:%d on %s:%d via %d", len, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
            goto end;
        }
        /* Read packet with delimiter */
        else if((packet_type & PACKET_DELIMITER) && conn->session.packet_delimiter
                && conn->session.packet_delimiter_length > 0)
        {
            p = MMB_DATA(conn->buffer);
            if((p = strstr(p, conn->session.packet_delimiter)))
            {
                len = p + conn->session.packet_delimiter_length - MMB_DATA(conn->buffer);
            }
            goto end;
        }
        return len;
end:
        /* Copy data to packet from buffer */
        if(len > 0)
        {
            ACCESS_LOGGER(conn->logger, "Read-packet[%d] length[%d] from %s:%d on %s:%d via %d", packet_type, len, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
            MMB_RESET(conn->packet);
            MMB_PUSH(conn->packet, MMB_DATA(conn->buffer), len);
            MMB_DELETE(conn->buffer, len);
            /* For packet quick handling */
            if(MMB_NDATA(conn->buffer) > 0 && conn->session.quick_handler 
                    && (n = conn->session.quick_handler(conn, PCB(conn->packet))) > 0)
            {
                ACCESS_LOGGER(conn->logger, "fill-chunk left[%d/%d] from %s:%d on %s:%d via %d", CHK_LEFT(conn->chunk), n, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
                chunk_mem(&(conn->chunk), n);
                conn->s_state = S_STATE_READ_CHUNK;
                conn__read__chunk(conn);
                ACCESS_LOGGER(conn->logger, "Read-chunk left[%d/%d] from %s:%d on %s:%d via %d", CHK_LEFT(conn->chunk), n, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);

            }
            else
            {
                conn->s_state = S_STATE_PACKET_HANDLING;
                conn_push_message(conn, MESSAGE_PACKET);
                ACCESS_LOGGER(conn->logger, "Got-packet to message_queue:%d from %s:%d on %s:%d via %d", QMTOTAL(conn->message_queue), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
            }
        }
    }
    return len;
}

/* packet handler */
int conn_packet_handler(CONN *conn)
{
    int ret = -1;
    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);
    PROCTHREAD *parent = NULL;

    if(conn && conn->session.packet_handler && (parent = PPARENT(conn)))
    {
        ACCESS_LOGGER(conn->logger, "packet_handler(%p) on %s:%d local[%s:%d] via %d", conn->session.packet_handler, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        ret = conn->session.packet_handler(conn, PCB(conn->packet));
        ACCESS_LOGGER(conn->logger, "over packet_handler(%p) parent->qtotal:%d on %s:%d local[%s:%d] via %d s_state:%d", conn->session.packet_handler, QMTOTAL(parent->message_queue), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, conn->s_state);

        if(conn->s_state == S_STATE_PACKET_HANDLING)
        {
            DEBUG_LOGGER(conn->logger, "Reset packet_handler(%p) buffer:[%d/%d] on %s:%d via %d", conn->session.packet_handler, MMB_LEFT(conn->buffer), MMB_SIZE(conn->buffer), conn->remote_ip, conn->remote_port, conn->fd);
            SESSION_RESET(conn);
        }
    }
    return ret;
}

/* okconn handler */
int conn_okconn_handler(CONN *conn)
{
    int ret = -1;

    if(conn && conn->session.ok_handler)
    {
        DEBUG_LOGGER(conn->logger, "okconn_handler(%p) on %s:%d via %d", conn->session.ok_handler, conn->remote_ip, conn->remote_port, conn->fd);
        ret = conn->session.ok_handler(conn);
        DEBUG_LOGGER(conn->logger, "over okconn_handler(%p) on %s:%d via %d", conn->session.ok_handler, conn->remote_ip, conn->remote_port, conn->fd);
    }
    return ret;
}

/* oob data handler */
int conn_oob_handler(CONN *conn)
{
    int ret = -1;

    if(conn && conn->session.oob_handler)
    {
        DEBUG_LOGGER(conn->logger, "oob_handler(%p) on %s:%d via %d", conn->session.oob_handler, conn->remote_ip, conn->remote_port, conn->fd);
        ret = conn->session.oob_handler(conn, PCB(conn->oob));
        DEBUG_LOGGER(conn->logger, "over oob_handler(%p) on %s:%d via %d", conn->session.oob_handler, conn->remote_ip, conn->remote_port, conn->fd);
    }
    return ret;
}

/* chunk   handler */
int conn_chunk_handler(CONN *conn)
{
    int ret = -1;
    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);
    PROCTHREAD *parent = NULL;

    if(conn && (parent = PPARENT(conn)))
    {
        if(conn->session.chunk_handler == NULL)
        {
            WARN_LOGGER(conn->logger, "NO session.chunk_handler(%p) parent->qtotal:%d on %s:%d local[%s:%d] via %d", conn->session.packet_handler, QMTOTAL(parent->message_queue), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
            return ret;
        }
        ret = conn->session.chunk_handler(conn, PCB(conn->packet), 
                PCB(conn->cache), PCB(conn->buffer));
        ACCESS_LOGGER(conn->logger, "over chunk_handler(%p) parent->qtotal:%d on %s:%d local[%s:%d] via %d", conn->session.packet_handler, QMTOTAL(parent->message_queue), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        //reset session
        if(conn->s_state == S_STATE_DATA_HANDLING)
        {
            SESSION_RESET(conn);
            DEBUG_LOGGER(conn->logger, "Reset chunk_handler(%p) buffer:%d on %s:%d via %d", conn->session.chunk_handler, conn->buffer.ndata, conn->remote_ip, conn->remote_port, conn->fd);
        }
    }
    return ret;
}

/* chunk data  handler */
int conn_data_handler(CONN *conn)
{
    int ret = -1;
    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);
    PROCTHREAD *parent = NULL;

    if(conn && (parent = PPARENT(conn)))
    {
        if(conn->session.packet_type == PACKET_PROXY)
        {
            return conn->proxy_handler(conn);
        }
        else if(CHK_TYPE(conn->chunk) == CHUNK_MEM && conn->session.data_handler)
        {
            ACCESS_LOGGER(conn->logger, "data_handler(%p) on %s:%d via %d", conn->session.data_handler, conn->remote_ip, conn->remote_port, conn->fd);
            //fprintf(stdout, "service[%s]->session.data_handler:%p\n", PPARENT(conn)->service->service_name, conn->session.data_handler);
            ret = conn->session.data_handler(conn, PCB(conn->packet), 
                    PCB(conn->cache), PCB(conn->chunk));
            ACCESS_LOGGER(conn->logger, "over data_handler(%p) parent->qtotal:%d on %s:%d local[%s:%d] via %d", conn->session.packet_handler, QMTOTAL(parent->message_queue), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        }
        else if(CHK_TYPE(conn->chunk) == CHUNK_FILE && conn->session.file_handler)
        {
            ACCESS_LOGGER(conn->logger, "file_handler(%p) on %s:%d via %d", conn->session.file_handler, conn->remote_ip, conn->remote_port, conn->fd);
            //fprintf(stdout, "service[%s]->session.data_handler:%p\n", PPARENT(conn)->service->service_name, conn->session.data_handler);
            ret = conn->session.file_handler(conn, PCB(conn->packet), 
                    PCB(conn->cache), CHK_FILENAME(conn->chunk));
            ACCESS_LOGGER(conn->logger, "over file_handler(%p) parent->qtotal:%d on %s:%d local[%s:%d] via %d", conn->session.packet_handler, QMTOTAL(parent->message_queue), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        }
        //reset session
        if(conn->s_state == S_STATE_DATA_HANDLING)
        {
            SESSION_RESET(conn);
            DEBUG_LOGGER(conn->logger, "Reset data_handler(%p) buffer:%d on %s:%d via %d", conn->session.data_handler, conn->buffer.ndata, conn->remote_ip, conn->remote_port, conn->fd);
        }
    }
    return ret;
}

/* bind proxy */
int conn_bind_proxy(CONN *conn, CONN *child)
{
    int ret = -1;
    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);

    if(conn && child)
    {
        conn->session.packet_type |= PACKET_PROXY;
        conn->session.childid = child->index;
        conn->session.child = child;
        DEBUG_LOGGER(conn->logger, "Bind proxy connection[%s:%d] to connection[%s:%d]", conn->remote_ip, conn->remote_port, child->remote_ip, child->remote_port);
        conn_push_message(conn, MESSAGE_PROXY);
        ret = 0;
    }
    return ret;
}

/* proxy data handler */
int conn_proxy_handler(CONN *conn)
{
    CONN *parent = NULL, *child = NULL, *oconn = NULL;
    CB_DATA *exchange = NULL, *chunk = NULL, *buffer = NULL;

    if(conn)
    {
        if(conn->session.parent && (parent = PPARENT(conn)->service->findconn(
                        PPARENT(conn)->service, conn->session.parentid))
                && parent == conn->session.parent)
        {
            oconn = parent;
        }
        else if(conn->session.child && (child = PPARENT(conn)->service->findconn(
                        PPARENT(conn)->service, conn->session.childid))
                && child == conn->session.child)
        {
            oconn = child;
        }
        else 
        {
            return -1;
        }
        DEBUG_LOGGER(conn->logger, "Ready exchange connection[%s:%d] to connection[%s:%d]", conn->remote_ip, conn->remote_port, oconn->remote_ip, oconn->remote_port);
        if((exchange = PCB(conn->exchange)) && exchange->ndata > 0)
        {
            DEBUG_LOGGER(conn->logger, "Ready exchange packet[%d] to conn[%s:%d]", exchange->ndata, oconn->remote_ip, oconn->remote_port);
            oconn->push_chunk(oconn, exchange->data, exchange->ndata);
            MMB_RESET(conn->exchange);
        }
        if((chunk = PCB(conn->chunk)) && chunk->ndata > 0)
        {
            DEBUG_LOGGER(conn->logger, "Ready exchange chunk[%d] to conn[%s:%d]", chunk->ndata, oconn->remote_ip, oconn->remote_port);
            oconn->push_chunk(oconn, chunk->data, chunk->ndata);
            chunk_reset(&conn->chunk);
        }
        if(conn->session.packet_type == PACKET_PROXY 
                && (buffer = PCB(conn->buffer)) && buffer->ndata > 0)
        {
            DEBUG_LOGGER(conn->logger, "Ready exchange buffer[%d] to conn[%s:%d]", buffer->ndata, oconn->remote_ip, oconn->remote_port);
            oconn->push_chunk(oconn, buffer->data, buffer->ndata);
            MMB_DELETE(conn->buffer, buffer->ndata);
        }
        return 0;
    }
    return -1;
}

/* close proxy */
int conn_close_proxy(CONN *conn)
{
    int ret = -1;
    CONN *parent = NULL, *child = NULL;

    if(conn && (conn->session.packet_type & PACKET_PROXY))
    {
        conn->proxy_handler(conn);
        if(conn->session.parent && (parent = PPARENT(conn)->service->findconn(
                        PPARENT(conn)->service, conn->session.parentid))
                && parent == conn->session.parent)
        {
            parent->set_timeout(parent, SB_PROXY_TIMEOUT);
            parent->session.childid = 0;
            parent->session.child = NULL;
        }
        else if(conn->session.child && (child = PPARENT(conn)->service->findconn(
                        PPARENT(conn)->service, conn->session.childid))
                && child == conn->session.child)
        {
            child->set_timeout(child, SB_PROXY_TIMEOUT);
            child->session.parent = NULL;
            child->session.parentid = 0;
        }
        ret = 0;
    }
    return ret;
}

/* push to exchange  */
int conn_push_exchange(CONN *conn, void *data, int size)
{
    int ret = -1;
    CONN_CHECK_RET(conn, (D_STATE_CLOSE|D_STATE_WCLOSE|D_STATE_RCLOSE), ret);

    if(conn)
    {
        MMB_PUSH(conn->exchange, data, size);
        DEBUG_LOGGER(conn->logger, "Push exchange size[%d] remote[%s:%d] local[%s:%d] via %d", MMB_NDATA(conn->exchange), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        ret = 0;
    }
    return ret;
}

/* save cache to connection  */
int conn_save_cache(CONN *conn, void *data, int size)
{
    int ret = -1;
    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);

    if(conn)
    {
        MMB_RESET(conn->cache);
        MMB_PUSH(conn->cache, data, size);
        DEBUG_LOGGER(conn->logger, "Saved cache size[%d] remote[%s:%d] local[%s:%d] via %d", MMB_NDATA(conn->cache), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        ret = 0;
    }
    return ret;
}

/* save header to connection  */
int conn_save_header(CONN *conn, void *data, int size)
{
    int ret = -1;
    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);

    if(conn)
    {
        MMB_RESET(conn->header);
        MMB_PUSH(conn->header, data, size);
        DEBUG_LOGGER(conn->logger, "Saved header size[%d] remote[%s:%d] local[%s:%d] via %d", MMB_NDATA(conn->header), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        ret = 0;
    }
    return ret;
}

/* reading chunk  */
int conn__read__chunk(CONN *conn)
{
    int ret = -1, n = -1;
    //CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);

    if(conn)
    {
        if(conn->s_state == S_STATE_READ_CHUNK
                && conn->session.packet_type != PACKET_PROXY
                && CHK_LEFT(conn->chunk) > 0
                && MMB_NDATA(conn->buffer) > 0)
        {
            DEBUG_LOGGER(conn->logger, "Ready fill-chunk from buffer:%d to %s:%d on conn[%s:%d] via %d", MMB_NDATA(conn->buffer), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
            if((n = CHUNK_FILL(&conn->chunk, MMB_DATA(conn->buffer), MMB_NDATA(conn->buffer))) > 0)
            {
                MMB_DELETE(conn->buffer, n);
            }
            if(CHUNK_STATUS(&conn->chunk) == CHUNK_STATUS_OVER)
            {
                DEBUG_LOGGER(conn->logger, "Chunk completed %lld bytes from %s:%d on %s:%d via %d", LL(CHK_SIZE(conn->chunk)), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
                conn->s_state = S_STATE_DATA_HANDLING;
                conn_push_message(conn, MESSAGE_DATA);
            }
            if(n > 0)
            {
                ACCESS_LOGGER(conn->logger, "Filled  %d byte(s) left:%lld to chunk from buffer to %s:%d on conn[%s:%d] via %d", n, LL(CHK_LEFT(conn->chunk)),conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
                ret = 0;
            }
        }
    }
    return ret;
}

/* pop newchunk */
CHUNK *conn_popchunk(CONN *conn)
{
    CHUNK *cp = NULL;
    int x = 0;

    if(conn)
    {
        MUTEX_LOCK(conn->mutex);
        if(conn->nqleft > 0)
        {
            x = --(conn->nqleft);
            cp = (CHUNK *)(conn->qleft[x]);
            conn->qleft[x] = NULL;
        }
        else 
        {
            x = conn->qblock_max++;
            cp = &(conn->qblocks[x].chunk);
        }
        MUTEX_UNLOCK(conn->mutex);
    }
    return cp;
}

/* set chunk to chunk2 */
void conn_setto_chunk2(CONN *conn)
{
    if(conn)
    {
        if(conn->chunk2.data) chunk_destroy(&(conn->chunk2));
        memcpy(&(conn->chunk2), &(conn->chunk), sizeof(CHUNK));
        memset(&(conn->chunk), 0, sizeof(CHUNK));
    }
    return ;
}

/* reset chunk2 */
void conn_reset_chunk2(CONN *conn)
{
    if(conn)
    {
        chunk_reset(&(conn->chunk2));
    }
    return ;
}

void conn_freechunk(CONN *conn, CB_DATA *chunk)
{
    CHUNK *cp = NULL;
    int x = 0;

    if(conn && (cp = (CHUNK *)chunk)
            && (void *)cp >= (void *)conn->qblocks
            && (void *)cp < (void *)(conn->qblocks + SB_QBLOCK_MAX))
    {
        chunk_reset(cp);
        MUTEX_LOCK(conn->mutex);
        x = conn->nqleft++;
        conn->qleft[x] = (QBLOCK *)cp;
        MUTEX_UNLOCK(conn->mutex);
    }
    return ;
}

/* newchunk */
CB_DATA *conn_newchunk(CONN *conn, int len)
{
    CB_DATA *cp = NULL;

    if(conn && len > 0 && (cp = (CB_DATA *)conn_popchunk(conn)))
    {
        chunk_mem((CHUNK *)cp, len);
        if(cp->data == NULL){conn_freechunk(conn, cp);cp = NULL;}
    }
    return cp;
}

/* newchunk memset */
CB_DATA *conn_mnewchunk(CONN *conn, int len)
{
    CB_DATA *cp = NULL;

    if(conn && len > 0 && (cp = (CB_DATA *)conn_popchunk(conn)))
    {
        chunk_mem((CHUNK *)cp, len);
        if(cp->data) memset(cp->data, 0, len);
        else {conn_freechunk(conn, cp);cp = NULL;}
    }
    return cp;
}

/* chunk reader */
int conn_chunk_reader(CONN *conn)
{
    int ret = -1;
    //CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);

    if(conn)
    {
        //MUTEX_LOCK(conn->mutex);
        ret = conn__read__chunk(conn);
        //MUTEX_UNLOCK(conn->mutex);
    }
    return ret;
}

/* reading chunk */
int conn_read_chunk(CONN *conn)
{
    int ret = -1;

    if(conn)
    {
        DEBUG_LOGGER(conn->logger, "Ready for reading-chunk from %s:%d on %s:%d via %d", conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        conn->s_state = S_STATE_CHUNK_READING;
        if(conn->d_state & D_STATE_CLOSE)
        {
            conn->chunk_reading(conn);
        }
        else
        {
            PUSH_INQMESSAGE(conn, MESSAGE_CHUNKIO);
        }
        ret = 0;
    }
    return ret;
}

/* receive chunk */
int conn_recv_chunk(CONN *conn, int size)
{
    int ret = -1;

    if(conn && size > 0)
    {
        DEBUG_LOGGER(conn->logger, "Ready for recv-chunk size:%d from %s:%d on %s:%d via %d", size, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        chunk_mem(&(conn->chunk), size);
        conn->s_state = S_STATE_READ_CHUNK;
        if(conn->d_state & D_STATE_CLOSE)
        {
            conn->chunk_reader(conn);
        }
        else
        {
            PUSH_INQMESSAGE(conn, MESSAGE_CHUNKIO);
        }
        ret = 0;
    }
    return ret;
}

/* store chunk */
int conn_store_chunk(CONN *conn, char *block, int size)
{
    int ret = -1;

    if(conn && block && size > 0)
    {
        DEBUG_LOGGER(conn->logger, "Ready for store-chunk size:%d from %s:%d on %s:%d via %d", size, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        chunk_destroy(&(conn->chunk));
        chunk_rebuild(&(conn->chunk), block, size); 
        conn->s_state = S_STATE_READ_CHUNK;
        if(conn->d_state & D_STATE_CLOSE)
        {
            conn->chunk_reader(conn);
        }
        else
        {
            PUSH_INQMESSAGE(conn, MESSAGE_CHUNKIO);
        }
        ret = 0;
    }
    return ret;
}


/* receive and fill to chunk */
int conn_recv2_chunk(CONN *conn, int size, char *data, int ndata)
{
    int ret = -1;

    if(conn && data && ndata >= 0)
    {
        DEBUG_LOGGER(conn->logger, "Ready for recv2-chunk size:%d from %s:%d on %s:%d via %d", size, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        chunk_mem(&(conn->chunk), size+ndata);
        if(data && ndata > 0)
        {
            CHUNK_FILL(&conn->chunk, data, ndata);
        }
        conn->s_state = S_STATE_READ_CHUNK;
        if(conn->d_state & D_STATE_CLOSE)
        {
            conn->chunk_reader(conn);
        }
        else
        {
            PUSH_INQMESSAGE(conn, MESSAGE_CHUNKIO);
        }
        ret = 0;
    }
    return ret;
}

/* push chunk */
int conn_push_chunk(CONN *conn, void *data, int size)
{
    int ret = -1;
    CHUNK *cp = NULL;
    CONN_CHECK_RET(conn, (D_STATE_CLOSE|D_STATE_WCLOSE|D_STATE_RCLOSE), ret);

    if(conn && conn->status == CONN_STATUS_FREE && SENDQ(conn) && data && size > 0)
    {
        //CHUNK_POP(conn, cp);
        //if(PPARENT(conn) && PPARENT(conn)->service 
        //        && (cp = PPARENT(conn)->service->popchunk(PPARENT(conn)->service)))
        if((cp = (CHUNK *)conn_popchunk(conn)))
        {
            chunk_mem(cp, size);
            chunk_mem_copy(cp, data, size);
            SENDQPUSH(conn, cp);
            CONN_OUTEVENT_MESSAGE(conn);
            ACCESS_LOGGER(conn->logger, "Pushed chunk size[%d/%d] to %s:%d queue[%p] total:%d on %s:%d via %d", size, cp->bsize,conn->remote_ip, conn->remote_port, SENDQ(conn), SENDQTOTAL(conn), conn->local_ip, conn->local_port, conn->fd);
            ret = 0;
        }
    }
    return ret;
}

/* receive chunk file */
int conn_recv_file(CONN *conn, char *filename, long long offset, long long size)
{
    int ret = -1;

    if(conn && filename && offset >= 0 && size > 0)
    {
        DEBUG_LOGGER(conn->logger, "Ready for recv-chunk file:%s offset:%lld size:%lld from %s:%d on %s:%d via %d", filename, LL(offset), LL(size), conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        chunk_file(&conn->chunk, filename, offset, size);
        conn->s_state = S_STATE_READ_CHUNK;
        if(conn->d_state & D_STATE_CLOSE)
        {
            conn->chunk_reader(conn);
        }
        else
        {
            PUSH_INQMESSAGE(conn, MESSAGE_CHUNKIO);
        }
        ret = 0;
    }
    return ret;
}


/* push chunk file */
int conn_push_file(CONN *conn, char *filename, long long offset, long long size)
{
    int ret = -1;
    CHUNK *cp = NULL;
    CONN_CHECK_RET(conn, (D_STATE_CLOSE|D_STATE_WCLOSE|D_STATE_RCLOSE), ret);

    if(conn && conn->status == CONN_STATUS_FREE && SENDQ(conn) 
            && filename && offset >= 0 && size > 0)
    {
        //CHUNK_POP(conn, cp);
        //if(PPARENT(conn) && PPARENT(conn)->service 
        //        && (cp = PPARENT(conn)->service->popchunk(PPARENT(conn)->service)))
        if((cp = (CHUNK *)conn_popchunk(conn)))
        {
            chunk_file(cp, filename, offset, size);
            SENDQPUSH(conn, cp);
            CONN_OUTEVENT_MESSAGE(conn);
            ACCESS_LOGGER(conn->logger, "Pushed file[%s] [%lld][%lld] to %s:%d queue total %d on %s:%d via %d ", filename, LL(offset), LL(size), conn->remote_ip, conn->remote_port, SENDQTOTAL(conn), conn->local_ip, conn->local_port, conn->fd);
            ret = 0;
        }
        else 
            return ret;
    }
    return ret;
}

/* send chunk */
int conn_send_chunk(CONN *conn, CB_DATA *chunk, int len)
{
    int ret = -1;
    CHUNK *cp = NULL;
    CONN_CHECK_RET(conn, (D_STATE_CLOSE|D_STATE_WCLOSE|D_STATE_RCLOSE), ret);

    if(conn && (cp = (CHUNK *)chunk))
    {
        CHK(cp)->left = len;
        SENDQPUSH(conn, cp);
        CONN_OUTEVENT_MESSAGE(conn);
        ACCESS_LOGGER(conn->logger, "send chunk len[%d][%d] to %s:%d queue[%p] total %d on %s:%d via %d", len, CHK(cp)->bsize,conn->remote_ip,conn->remote_port, SENDQ(conn), SENDQTOTAL(conn), conn->local_ip, conn->local_port, conn->fd);
        ret = 0;
    }
    return ret;
}

/* relay chunk */
int conn_relay_chunk(CONN *conn, char *data, int ndata)
{
    int ret = -1;
    CHUNK *cp = NULL;
    CONN_CHECK_RET(conn, (D_STATE_CLOSE|D_STATE_WCLOSE|D_STATE_RCLOSE), ret);

    if(conn && data && ndata > 0)
    {
        cp = (CHUNK *)&(conn->xblock);
        chunk_rebuild(cp, data, ndata); 
        SENDQPUSH(conn, cp);
        CONN_OUTEVENT_MESSAGE(conn);
        ACCESS_LOGGER(conn->logger, "relay data[%p] len[%d][%d] to %s:%d queue[%p] total %d on %s:%d via %d", data, ndata, CHK(cp)->bsize, conn->remote_ip,conn->remote_port, SENDQ(conn), SENDQTOTAL(conn), conn->local_ip, conn->local_port, conn->fd);
        ret = 0;
    }
    return ret;
}


/* over chunk and close connection */
int conn_over_chunk(CONN *conn)
{
    int ret = -1;
    CHUNK *cp = NULL;
    CONN_CHECK_RET(conn, (D_STATE_CLOSE|D_STATE_WCLOSE|D_STATE_RCLOSE), ret);

    if(conn && conn->status == CONN_STATUS_FREE && SENDQ(conn))
    {
        //if(PPARENT(conn) && PPARENT(conn)->service 
        //        && (cp = PPARENT(conn)->service->popchunk(PPARENT(conn)->service)))
        if((cp = (CHUNK *)conn_popchunk(conn)))
        {
            SENDQPUSH(conn, cp);
            CONN_OUTEVENT_MESSAGE(conn);
            ret = 0;
        }
        else 
            return ret;
    }
    return ret;
}

/* set session options */
int conn_set_session(CONN *conn, SESSION *session)
{
    int ret = -1;

    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);
    if(conn && session)
    {
        memcpy(&(conn->session), session, sizeof(SESSION));
        if(conn->parent && conn->session.timeout > 0) 
            conn->set_timeout(conn, conn->session.timeout);
        ret = 0;
    }
    return ret;
}

/* over session */
int conn_over_session(CONN *conn)
{
    int ret = -1;

    CONN_CHECK_RET(conn, D_STATE_CLOSE, -1);
    if(conn)
    {
        SESSION_RESET(conn);
        if(conn->session.flags & SB_MULTICAST) 
            PPARENT(conn)->service->freeconn(PPARENT(conn)->service, conn);
        else
        {
            if(PPARENT(conn)->service->service_type == C_SERVICE)
            {
                DEBUG_LOGGER(conn->logger, "free conn[%p][%s:%d] group[%d] local[%s:%d] via %d", conn, conn->remote_ip, conn->remote_port, conn->groupid, conn->local_ip, conn->local_port, conn->fd);
                PPARENT(conn)->service->freeconn(PPARENT(conn)->service, conn);
            }
        }
        ret = 0;
    }
    return ret;
}

/* new task */
int conn_newtask(CONN *conn, CALLBACK *handler)
{
    if(conn && handler)
    {
        conn->s_state = S_STATE_TASKING;
        return PPARENT(conn)->service->newtask(PPARENT(conn)->service, handler, conn);
    }
    return -1;
}

/* add multicast */
int conn_add_multicast(CONN *conn, char *multicast_ip)
{
    struct ip_mreq mreq;
    int ret = -1;

    if(conn && !(conn->flags & SB_MULTICAST_IN) && conn->fd > 0)
    {
        memset(&mreq, 0, sizeof(struct ip_mreq));
        mreq.imr_multiaddr.s_addr = inet_addr(multicast_ip);
        if((ret = setsockopt(conn->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
                        (char*)&mreq, sizeof(struct ip_mreq))) == 0)
        {
            DEBUG_LOGGER(conn->logger, "added multicast:%s to conn[%p]->fd[%d]",multicast_ip, conn, conn->fd);
            conn->flags |= SB_MULTICAST_IN;
            return 0;
        }
        else
        {
            WARN_LOGGER(conn->logger, "added multicast:%s to conn[%p]->fd[%d] failed, %s",multicast_ip, conn, conn->fd, strerror(errno));
        }
    }
    return -1;
}

/* transaction handler */
int conn_transaction_handler(CONN *conn, int tid)
{

    int ret = -1;

    if(conn)
    {
        if(conn && conn->session.transaction_handler)
        {
            ret = conn->session.transaction_handler(conn, tid);
        }
    }
    return ret;
}

/* reset xids */
void conn_reset_xids(CONN *conn)
{
    if(conn)
    {
        memset(conn->xids, 0, sizeof(int) * SB_XIDS_MAX);
        memset(conn->xids64, 0, sizeof(int64_t) * SB_XIDS_MAX);
    }
    return ;
}

/* reset stat */
void conn_reset_state(CONN *conn)
{
    if(conn)
    {
        conn->groupid = -1;
        conn->index = -1;
        conn->gindex = -1;
        conn->c_state = 0;
        conn->d_state = 0;
        conn->e_state = 0;
    }
    return ;
}

/* reset connection */
void conn_reset(CONN *conn)
{
    CHUNK *cp = NULL;

    if(conn)
    {
        DEBUG_LOGGER(conn->logger, "Reset connection[%p][%s:%d] local[%s:%d] via %d", conn, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd);
        /* global */
        conn->groupid = -1;
        conn->index = -1;
        conn->gindex = -1;
        conn->xindex = -1;
        conn->d_state = 0;
        conn->e_state = 0;
        conn->flags = 0;
        memset(conn->xids, 0, sizeof(int) * SB_XIDS_MAX);
        /* connection */
        conn->fd = 0;
        conn->sock_type = 0;
        memset(conn->remote_ip, 0, SB_IP_MAX);
        conn->remote_port = 0;
        memset(conn->local_ip, 0, SB_IP_MAX);
        conn->local_port = 0;
        /* bytes stats */
        conn->recv_oob_total = 0ll;
        conn->sent_oob_total = 0ll;
        conn->recv_data_total = 0ll;
        conn->sent_data_total = 0ll;
        /* event */
        conn->evbase = NULL;
        conn->outevbase = NULL;

        /* event timer */
        conn->evid = -1;
        conn->evtimer = NULL;
        /* buffer and chunk */
        MMB_RESET(conn->buffer);
        MMB_RESET(conn->packet);
        MMB_RESET(conn->oob);
        MMB_RESET(conn->cache);
        MMB_RESET(conn->exchange);
        chunk_reset(&(conn->chunk));
        chunk_reset(&(conn->chunk2));
        /* timer, logger, message_queue and queue */
        conn->message_queue = NULL;
        conn->inqmessage = NULL;
        conn->outqmessage = NULL;
        if(SENDQ(conn))
        {
            while((cp = (CHUNK *)SENDQPOP(conn)))
            {
                conn_freechunk(conn, (CB_DATA *)cp);
                cp  = NULL;
            }
        }
        /* SSL */
#ifdef HAVE_SSL
        if(conn->ssl)
        {
            SSL_free(XSSL(conn->ssl));
            conn->ssl = NULL;
        }
#endif
        /* client transaction state */
        conn->parent = NULL;
        conn->status = 0;
        conn->i_state = 0;
        conn->c_state = 0;
        conn->c_id = 0;

        /* transaction */
        conn->s_id = 0;
        conn->s_state = 0;
        /* event state */
        conn->evstate = 0;
        conn->timeout = 0;
        /* session */
        memset(&(conn->session), 0, sizeof(SESSION));
    }
    return ;
}
/* clean connection */
void conn_clean(CONN *conn)
{
    int i = 0;

    if(conn)
    {
        MUTEX_DESTROY(conn->mutex);
        conn->mutex = NULL;
        event_clean(&(conn->event));
        /* Clean BUFFER */
        MMB_DESTROY(conn->buffer);
        /* Clean OOB */
        MMB_DESTROY(conn->oob);
        /* Clean cache */
        MMB_DESTROY(conn->cache);
        /* Clean header */
        MMB_DESTROY(conn->header);
        /* Clean packet */
        MMB_DESTROY(conn->packet);
        /* Clean exchange */
        MMB_DESTROY(conn->exchange);
        /* Clean chunk */
        chunk_destroy(&(conn->chunk));
        /* clean chunk2*/
        chunk_destroy(&(conn->chunk2));
        /* Clean queue */
        SENDQCLEAN(conn);
        for(i = 0; i < conn->qblock_max; i++)
        {
            chunk_destroy((void *)&(conn->qblocks[i]));
        }
#ifdef HAVE_SSL
        if(conn->ssl)
        {
            SSL_free(XSSL(conn->ssl));
            conn->ssl = NULL;
        }
#endif
        DEBUG_LOGGER(conn->logger, "over-clean conn[%p]", conn);
        xmm_free(conn, sizeof(CONN));
    }
    return ;
}

/* Initialize connection */
CONN *conn_init()
{
    CONN *conn = NULL;

    if((conn = (CONN *)xmm_mnew(sizeof(CONN))))
    {
        conn->groupid = -1;
        conn->index = -1;
        conn->gindex = -1;
        MUTEX_INIT(conn->mutex);
        //SENDQINIT(conn);
        conn->set                   = conn_set;
        conn->get_service_id        = conn_get_service_id;
        conn->close                 = conn_close;
        conn->over                  = conn_over;
        conn->terminate             = conn_terminate;
        conn->start_cstate          = conn_start_cstate;
        conn->over_cstate           = conn_over_cstate;
        conn->wait_estate           = conn_wait_estate;
        conn->over_estate           = conn_over_estate;
        conn->set_timeout           = conn_set_timeout;
        conn->over_timeout          = conn_over_timeout;
        conn->timeout_handler       = conn_timeout_handler;
        conn->wait_evtimeout        = conn_wait_evtimeout;
        conn->wait_evstate          = conn_wait_evstate;
        conn->over_evstate          = conn_over_evstate;
        conn->push_message          = conn_push_message;
        conn->outevent_handler      = conn_outevent_handler;
        conn->read_handler          = conn_read_handler;
        conn->write_handler         = conn_write_handler;
        conn->send_handler          = conn_send_handler;
        conn->packet_reader         = conn_packet_reader;
        conn->packet_handler        = conn_packet_handler;
        conn->oob_handler           = conn_oob_handler;
        conn->okconn_handler        = conn_okconn_handler;
        conn->chunk_handler         = conn_chunk_handler;
        conn->data_handler          = conn_data_handler;
        conn->bind_proxy            = conn_bind_proxy;
        conn->proxy_handler         = conn_proxy_handler;
        conn->close_proxy           = conn_close_proxy;
        conn->push_exchange         = conn_push_exchange;
        conn->transaction_handler   = conn_transaction_handler;
        conn->save_cache            = conn_save_cache;
        conn->save_header           = conn_save_header;
        conn->chunk_reader          = conn_chunk_reader;
        conn->chunk_reading         = conn_chunk_reading;
        conn->read_chunk            = conn_read_chunk;
        conn->recv_chunk            = conn_recv_chunk;
        conn->recv2_chunk           = conn_recv2_chunk;
        conn->store_chunk           = conn_store_chunk;
        conn->push_chunk            = conn_push_chunk;
        conn->recv_file             = conn_recv_file;
        conn->push_file             = conn_push_file;
        conn->send_chunk            = conn_send_chunk;
        conn->relay_chunk           = conn_relay_chunk;
        conn->over_chunk            = conn_over_chunk;
        conn->newchunk              = conn_newchunk;
        conn->mnewchunk             = conn_mnewchunk;
        conn->freechunk             = conn_freechunk;
        conn->setto_chunk2          = conn_setto_chunk2;
        conn->reset_chunk2          = conn_reset_chunk2;
        conn->buffer_handler        = conn_buffer_handler;
        conn->chunkio_handler       = conn_chunkio_handler;
        conn->free_handler          = conn_free_handler;
        conn->end_handler           = conn_end_handler;
        conn->shut_handler          = conn_shut_handler;
        conn->shutout_handler       = conn_shutout_handler;
        conn->set_session           = conn_set_session;
        conn->over_session          = conn_over_session;
        conn->newtask               = conn_newtask;
        conn->add_multicast         = conn_add_multicast;
        conn->reset_xids            = conn_reset_xids;
        conn->reset_state           = conn_reset_state;
        conn->reset                 = conn_reset;
        conn->clean                 = conn_clean;
    }
    return conn;
}
