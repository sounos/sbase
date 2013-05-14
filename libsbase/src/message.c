#include "message.h"
#include "sbase.h"
#include "logger.h"
#include "mutex.h"
#include "xmm.h"
/* initialize */
void *qmessage_init()
{
    MESSAGE *msg = NULL;
    QMESSAGE *q = NULL;
    int i = 0;

    if((q = (QMESSAGE *)xmm_mnew(sizeof(QMESSAGE))))
    {
        MUTEX_INIT(q->mutex);
        for(i = 0; i < QMSG_INIT_NUM; i++)
        {
            msg = &(q->pools[i]);
            msg->next = q->left;
            q->left = msg;
            q->nleft++;
            q->qtotal = QMSG_INIT_NUM;
        }
    }
    return q;
}

/* qmessage */
void qmessage_push(void *qmsg, int id, int index, int fd, int tid, 
        void *parent, void *handler, void *arg)
{
    MESSAGE *msg = NULL, *tmp = NULL;
    QMESSAGE *q = (QMESSAGE *)qmsg;
    int i = 0;

    if(q)
    {
        MUTEX_LOCK(q->mutex);
        if((msg = q->left))
        {
            q->left = msg->next;
            q->nleft--;
        }
        else
        {
            if((i = q->nlist) < QMSG_LINE_MAX)
            {
                //fprintf(stdout, "%s::%d q:%p qtotal:%d total:%d left:%d nlist:%d\n", __FILE__, __LINE__, q, q->qtotal, q->total, q->nleft, q->nlist);
                if((msg = (MESSAGE *)xmm_new(QMSG_LINE_NUM * sizeof(MESSAGE))))
                {
                    q->list[i] = msg;
                    q->nlist++;
                    i = 1;
                    while(i < QMSG_LINE_NUM)
                    {
                        tmp = &(msg[i]);
                        tmp->next = q->left;
                        q->left = tmp;
                        ++i;
                        q->nleft++;
                    }
                    q->qtotal += QMSG_LINE_NUM;
                }
            }
        }
        if(msg)
        {
            msg->msg_id = id;
            msg->index = index;
            msg->fd = fd;
            msg->tid = tid;
            msg->handler = handler;
            msg->parent = parent;
            msg->arg = arg;
            msg->next = NULL;
            if(q->last)
            {
                q->last->next = msg;
                q->last = msg;
            }
            else
            {
                q->first = q->last = msg;
            }
            ++(q->total);
            //fprintf(stdout, "%s::%d q:%p qtotal:%d total:%d left:%d nlist:%d\n", __FILE__, __LINE__, q, q->qtotal, q->total, q->nleft, q->nlist);
        }
        MUTEX_UNLOCK(q->mutex);
    }
    return ;
}

MESSAGE *qmessage_pop(void *qmsg)
{
    QMESSAGE *q = (QMESSAGE *)qmsg;
    MESSAGE *msg = NULL;

    if(q)
    {
        MUTEX_LOCK(q->mutex);
        if((msg = q->first))
        {
            if((q->first = q->first->next) == NULL)
            {
                q->last = NULL;
            }
            --(q->total);
            msg->next = NULL;
        }
        MUTEX_UNLOCK(q->mutex);
    }
    return msg;
}

/* clean qmessage */
void qmessage_clean(void *qmsg)
{
    QMESSAGE *q = (QMESSAGE *)qmsg;
    int i = 0;

    if(q)
    {
        for(i = 0; i < q->nlist; i++)
        {
            xmm_free(q->list[i], QMSG_LINE_NUM * sizeof(MESSAGE));
        }
        MUTEX_DESTROY(q->mutex);
        xmm_free(q, sizeof(QMESSAGE));
    }
    return ;
}

/* to qleft */
void qmessage_left(void *qmsg, MESSAGE *msg)
{
    QMESSAGE *q = (QMESSAGE *)qmsg;

    if(q && msg)
    {
        MUTEX_LOCK(q->mutex);
        msg->next = q->left;
        q->left = msg;
        q->nleft++;
        MUTEX_UNLOCK(q->mutex);
    }
    return ;
}

void qmessage_handler(void *qmsg, void *logger)
{
    int fd = -1, index = 0, total = 0;
    QMESSAGE *q = (QMESSAGE *)qmsg;
    PROCTHREAD *pth = NULL;
    MESSAGE *msg = NULL;
    CONN *conn = NULL;

    if((total = QMTOTAL(q)) > 0)
    {
        while((msg = qmessage_pop(qmsg)))
        {
            if(msg->msg_id < 1 || msg->msg_id > MESSAGE_MAX) 
            {
                FATAL_LOGGER(logger, "Invalid message[%d/%d] handler[%p] parent[%p] fd[%d]",
                        msg->msg_id, MESSAGE_MAX, msg->handler, msg->parent, msg->fd);
                goto next;
            }
            pth = (PROCTHREAD *)(msg->parent);
            if(msg->msg_id == MESSAGE_NEW_CONN)
            {
                DEBUG_LOGGER(logger, "Got message[%s] fd:%d total[%d/%d] left:%d On service[%s] procthread[%p] ", messagelist[msg->msg_id], msg->fd, q->total, q->qtotal, q->nleft, pth->service->service_name, pth); 
                pth->newconn(pth, msg->fd, msg->handler);
                goto next;
            }
            conn = (CONN *)(msg->handler);
            index = msg->index;
            if(msg->msg_id == MESSAGE_STOP && pth)
            {
                 pth->terminate(pth);
                 goto next;
            }
            //task and heartbeat
            if(msg->msg_id == MESSAGE_TASK || msg->msg_id == MESSAGE_HEARTBEAT 
                    || msg->msg_id == MESSAGE_STATE)
            {
                if(msg->handler)
                {
                    ((CALLBACK *)(msg->handler))(msg->arg);
                }
                goto next;
            }
            if(conn) fd = conn->fd;
            if(conn == NULL || pth == NULL || msg->fd != conn->fd || pth->service == NULL)
            {
                ERROR_LOGGER(logger, "Invalid MESSAGE[%d/%s] msg->fd[%d] conn->fd[%d] handler[%p] "
                        "parent[%p] service[%p]", msg->msg_id, messagelist[msg->msg_id], msg->fd, fd, conn, pth, pth->service);
                goto next;
            }
            if(index >= 0 && pth->service->connections[index] != conn) goto next;
            DEBUG_LOGGER(logger, "Got message[%s] total[%d/%d] left:%d On service[%s] procthread[%p] "
                    "connection[%p][%s:%d] d_state:%d local[%s:%d] via %d", messagelist[msg->msg_id],
                    q->total, q->qtotal, q->nleft, pth->service->service_name, pth, 
                    conn, conn->remote_ip, conn->remote_port, conn->d_state,
                    conn->local_ip, conn->local_port, conn->fd);
            //message  on connection 
            switch(msg->msg_id)
            {
                case MESSAGE_NEW_SESSION :
                    pth->add_connection(pth, conn);
                    break;
                case MESSAGE_SHUT :
                    conn->shut_handler(conn);
                    break;
                case MESSAGE_SHUTOUT :
                    conn->shutout_handler(conn);
                    break;
                case MESSAGE_OUT :
                    conn->outevent_handler(conn);
                    break;
                case MESSAGE_OVER :
                    pth->over_connection(pth, conn);
                    break;
                case MESSAGE_QUIT :
                    pth->terminate_connection(pth, conn);
                    break;
                case MESSAGE_INPUT :
                    conn->read_handler(conn);
                    break;
                case MESSAGE_OUTPUT :
                    conn->write_handler(conn);
                    break;
                case MESSAGE_BUFFER:
                    conn->buffer_handler(conn);
                    break;
                case MESSAGE_PACKET :
                    conn->packet_handler(conn);
                    break;
                case MESSAGE_CHUNK :
                    conn->chunk_handler(conn);
                    break;
                case MESSAGE_CHUNKIO :
                    conn->chunkio_handler(conn);
                    break;
                case MESSAGE_DATA :
                    conn->data_handler(conn);
                    break;
                case MESSAGE_END :
                    conn->end_handler(conn);
                    break;
                case MESSAGE_FREE :
                    conn->free_handler(conn);
                    break;
                case MESSAGE_TRANSACTION :
                    conn->transaction_handler(conn, msg->tid);
                    break;
                case MESSAGE_TIMEOUT :
                    conn->timeout_handler(conn);
                    break;
                case MESSAGE_PROXY :
                    conn->proxy_handler(conn);
                    break;
            }
next:
            qmessage_left(qmsg, msg);
        }
    }
    return ;
}
