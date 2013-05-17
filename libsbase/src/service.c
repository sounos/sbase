#define _GNU_SOURCE
#include <sched.h> 
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include "sbase.h"
#include "xssl.h"
#include "logger.h"
#include "service.h"
#include "mmblock.h"
#include "message.h"
#include "evtimer.h"
#include "procthread.h"
#include "xmm.h"
#include "mutex.h"
#ifndef UI
#define UI(_x_) ((unsigned int)(_x_))
#endif
#ifdef HAVE_SSL
#define SERVICE_CHECK_SSL_CLIENT(service)                                           \
do                                                                                  \
{                                                                                   \
    if(service->c_ctx == NULL)                                                      \
    {                                                                               \
        if((service->c_ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)          \
        {                                                                           \
            ERR_print_errors_fp(stdout);                                            \
            _exit(-1);                                                              \
        }                                                                           \
    }                                                                               \
}while(0)
#else 
#define SERVICE_CHECK_SSL_CLIENT(service)
#endif
int new_listenfd(SERVICE *service)
{
    int fd = 0, opt = 1, flag = 0, ret = 0;
    struct linger linger = {0};

    if((fd = socket(service->family, service->sock_type, 0)) > 0
            && fcntl(fd, F_SETFD, FD_CLOEXEC) == 0

            && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == 0
#ifdef SO_REUSEPORT
            && setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == 0
#endif
      )
    {
        if(service->flag & SB_SO_LINGER)
        {
            linger.l_onoff = 1;linger.l_linger = 0;
            setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger));
        }
        /*
           if(service->flag & SB_TCP_NODELAY)
           {
        //opt = 1;setsockopt(service->fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
        opt = 1;setsockopt(service->fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
        }
        */
        //opt = 1;setsockopt(service->fd, IPPROTO_TCP, TCP_CORK, &opt, sizeof(opt));
        //opt = 1;setsockopt(service->fd, IPPROTO_TCP, TCP_QUICKACK, &opt, sizeof(opt));
        if(service->working_mode == WORKING_PROC)
        {
            flag = fcntl(fd, F_GETFL, 0);
            ret = fcntl(fd, F_SETFL, flag|O_NONBLOCK);
        }
        ret = bind(fd, (struct sockaddr *)&(service->sa), sizeof(struct sockaddr));
        if(service->sock_type == SOCK_STREAM) ret |= listen(fd, SB_BACKLOG_MAX);
        if(ret)
        {
            WARN_LOGGER(service->logger, "bind fd[%d] failed, %s", fd, strerror(errno));
            close(fd);
            fd = 0;
        }
    }
    return fd;
}

/* set service */
int service_set(SERVICE *service)
{
    int ret = -1, i = 0;
    char *p = NULL;

    if(service)
    {
        p = service->ip;
        service->sa.sin_family = service->family;
        service->sa.sin_addr.s_addr = (p)? inet_addr(p):INADDR_ANY;
        service->sa.sin_port = htons(service->port);
        service->backlog = SB_BACKLOG_MAX;
        if(service->nworking_tosleep < 1) 
            service->nworking_tosleep = SB_NWORKING_TOSLEEP; 
        SERVICE_CHECK_SSL_CLIENT(service);
        if(service->service_type == S_SERVICE)
        {
#ifdef HAVE_SSL
            if(service->is_use_SSL && service->cacert_file && service->privkey_file)
            {
                if((service->s_ctx = SSL_CTX_new(SSLv23_server_method())) == NULL)
                {
                    ERR_print_errors_fp(stdout);
                    return -1;
                }
                /*load certificate */
                if(SSL_CTX_use_certificate_file(XSSL_CTX(service->s_ctx), service->cacert_file, 
                            SSL_FILETYPE_PEM) <= 0)
                {
                    ERR_print_errors_fp(stdout);
                    return -1;
                }
                /*load private key file */
                if (SSL_CTX_use_PrivateKey_file(XSSL_CTX(service->s_ctx), service->privkey_file, 
                            SSL_FILETYPE_PEM) <= 0)
                {
                    ERR_print_errors_fp(stdout);
                    return -1;
                }
                /*check private key file */
                if (!SSL_CTX_check_private_key(XSSL_CTX(service->s_ctx)))
                {
                    ERR_print_errors_fp(stdout);
                    return -1;
                }
            }
#endif
            if((service->fd = new_listenfd(service)) > 0)
            {
                if(service->session.flags & SB_MULTICAST_LIST)
                {
                    for(i = 0; i < SB_MULTICAST_MAX; i++)
                    {
                        service->multicasts[i] = new_listenfd(service);
                    }
                }
                ret  = 0;
            }
            else
            {
                fprintf(stderr, "new socket() failed, %s", strerror(errno));
                return -1;
            }
        }
        else if(service->service_type == C_SERVICE)
        {
           ret = 0;
        }
    }
    return ret;
}

/* ignore SIGPIPE */
void sigpipe_ignore()
{
#ifndef WIN32
    sigset_t signal_mask;
    sigemptyset(&signal_mask);
    sigaddset(&signal_mask, SIGPIPE);
    sigaddset(&signal_mask, SIGFPE);
#ifdef HAVE_PTHREAD
    pthread_sigmask(SIG_BLOCK, &signal_mask, NULL);
#endif
#endif
    return ;
}

#ifdef HAVE_PTHREAD
#define NEW_PROCTHREAD(service, xattr, ns, no, threadid, proc, logger)                      \
do{                                                                                         \
    if(pthread_create(&(threadid), &xattr, (void *)(&procthread_run), (void *)proc) != 0)   \
    {                                                                                       \
        FATAL_LOGGER(logger, "create newthread[%s][%d] failed, %s",ns,no,strerror(errno));  \
        exit(EXIT_FAILURE);                                                                 \
    }                                                                                       \
}while(0)
#else
#define NEW_PROCTHREAD(service, xattr, ns, id, pthid, pth, logger)
#endif
#ifdef HAVE_PTHREAD
#define PROCTHREAD_EXIT(no, exitid) pthread_join((pthread_t)no, exitid)
#else
#define PROCTHREAD_EXIT(no, exitid)
#endif
#define PROCTHREAD_SET(service, pth)                                                        \
{                                                                                           \
    pth->service = service;                                                                 \
    pth->logger = service->logger;                                                          \
    pth->usec_sleep = service->usec_sleep;                                                  \
    pth->use_cond_wait = service->use_cond_wait;                                            \
}

/* running */
int service_run(SERVICE *service)
{
    int ret = -1, i = 0, x = 0;
    //ncpu = sysconf(_SC_NPROCESSORS_CONF);
    CONN *conn = NULL; 
#ifdef HAVE_PTHREAD
    pthread_attr_t ioattr, attr;
    struct sched_param ioparam, param;
#endif

    if(service)
    {
        //added to evtimer 
        if((service->session.flags & SB_MULTICAST) 
                || service->heartbeat_interval > 0 
                || service->service_type == C_SERVICE)
        {
            if(service->heartbeat_interval < 1) service->heartbeat_interval = SB_HEARTBEAT_INTERVAL;
            service->evid = EVTIMER_ADD(service->evtimer, service->heartbeat_interval, 
                    &service_evtimer_handler, (void *)service);
            DEBUG_LOGGER(service->logger, "Added service[%s] to evtimer[%p][%d] interval:%d", service->service_name, service->evtimer, service->evid, service->heartbeat_interval);
        }
        //evbase setting 
        if(service->service_type == S_SERVICE && service->evbase
                && service->working_mode == WORKING_PROC)
        {
            event_set(&(service->event), service->fd, E_READ|E_PERSIST,
                    (void *)service, (void *)&service_event_handler);
            ret = service->evbase->add(service->evbase, &(service->event));
            if(service->session.flags & SB_MULTICAST_LIST)
            {
                for(i = 0; i < SB_MULTICAST_MAX; i++)
                {
                    if(service->multicasts[i] > 0)
                    {
                        event_set(&(service->evmulticasts[i]), service->multicasts[i],
                                E_READ|E_PERSIST, (void *)service, (void *)&service_event_handler);
                        ret = service->evbase->add(service->evbase, &(service->evmulticasts[i]));
                    }
                }
            }
        }
        //initliaze conns
        for(i = 0; i < SB_INIT_CONNS; i++)
        {
            if((conn = conn_init()))
            {
                x = service->nqconns++;
                service->qconns[x] = conn;
                service->nconn++;
            }
            else break;
        }
        if(service->working_mode == WORKING_THREAD)
            goto running_threads;
        else 
            goto running_proc;
        return ret;
running_proc:
        //procthreads setting 
        if((service->daemon = procthread_init(0)))
        {
            PROCTHREAD_SET(service, service->daemon);
            if(service->daemon->message_queue)
            {
                if(service->daemon->message_queue) 
                {
                    qmessage_clean(service->daemon->message_queue);
                }
                service->daemon->message_queue = service->message_queue;
                service->daemon->inqmessage = service->message_queue;
                service->daemon->outqmessage = service->message_queue;
                service->daemon->evbase = service->evbase;
            }
            service->daemon->service = service;
            ret = 0;
        }
        else
        {
            FATAL_LOGGER(service->logger, "Initialize daemon mode[%d] failed, %s",service->working_mode, strerror(errno));
            _exit(-1);
        }
        return ret;
running_threads:
#ifdef HAVE_PTHREAD
        sigpipe_ignore();
        /* set thread attr */
        //pthread_setconcurrency();
        memset(&param, 0, sizeof(struct sched_param));
        memset(&ioparam, 0, sizeof(struct sched_param));
        pthread_attr_init(&attr);
        pthread_attr_init(&ioattr);
        pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
        pthread_attr_setinheritsched(&ioattr, PTHREAD_EXPLICIT_SCHED);
        pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
        pthread_attr_setscope(&ioattr, PTHREAD_SCOPE_SYSTEM);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
        pthread_attr_setdetachstate(&ioattr, PTHREAD_CREATE_JOINABLE);
        if(getuid() == 0)
        {
            if(service->flag & SB_SCHED_FIFO)
            {
                pthread_attr_setschedpolicy(&ioattr, SCHED_FIFO);
                ioparam.sched_priority = sched_get_priority_max(SCHED_FIFO);
                pthread_attr_setschedparam(&ioattr, &ioparam);
                pthread_setschedparam(pthread_self(), SCHED_RR, &ioparam);
                pthread_attr_setschedpolicy(&attr, SCHED_RR);
                param.sched_priority = sched_get_priority_max(SCHED_RR) - 1;
                pthread_attr_setschedparam(&attr, &param);
            }
            else if(service->flag & SB_SCHED_RR)
            {
                pthread_attr_setschedpolicy(&ioattr, SCHED_RR);
                ioparam.sched_priority = sched_get_priority_max(SCHED_RR);
                pthread_attr_setschedparam(&ioattr, &ioparam);
                pthread_setschedparam(pthread_self(), SCHED_RR, &ioparam);
                pthread_attr_setschedpolicy(&attr, SCHED_RR);
                param.sched_priority = sched_get_priority_max(SCHED_RR) - 1;
                pthread_attr_setschedparam(&attr, &param);
            }
            else
            {
                pthread_attr_setschedpolicy(&ioattr, SCHED_RR);
                ioparam.sched_priority = sched_get_priority_max(SCHED_RR);
                pthread_attr_setschedparam(&ioattr, &ioparam);
                pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
                pthread_setschedparam(pthread_self(), SCHED_OTHER, &param);
            }
        }
        /* initialize iodaemons */
        if(service->niodaemons > SB_THREADS_MAX) service->niodaemons = SB_THREADS_MAX;
        if(service->niodaemons < 1) service->niodaemons = 1;
        if(service->niodaemons > 0)
        {
            for(i = 0; i < service->niodaemons; i++)
            {
                if((service->iodaemons[i] = procthread_init(service->cond)))
                {
                    PROCTHREAD_SET(service, service->iodaemons[i]);
                    service->iodaemons[i]->use_cond_wait = 0;
                    NEW_PROCTHREAD(service, ioattr, "iodaemons", i, service->iodaemons[i]->threadid, service->iodaemons[i], service->logger);
                    ret = 0;
                }
                else
                {
                    FATAL_LOGGER(service->logger, "Initialize iodaemons[%d] failed, %s", i, strerror(errno));
                    goto err;
                }
            }
        }
        /* outdaemon */ 
        if((service->flag & SB_USE_OUTDAEMON))
        {
            if((service->outdaemon = procthread_init(service->cond)))
            {
                PROCTHREAD_SET(service, service->outdaemon);
                service->outdaemon->use_cond_wait = 0;
                NEW_PROCTHREAD(service, ioattr, "outdaemon", 0, service->outdaemon->threadid, service->outdaemon, service->logger);
                ret = 0;
            }
            else
            {
                FATAL_LOGGER(service->logger, "Initialize outdaemon failed, %s", strerror(errno));
                goto err;
            }
        }
        /* daemon */ 
        if((service->daemon = procthread_init(0)))
        {
            PROCTHREAD_SET(service, service->daemon);
            if(service->flag & SB_USE_EVSIG)
                procthread_set_evsig_fd(service->daemon, service->cond);
            NEW_PROCTHREAD(service, ioattr, "daemon", 0, service->daemon->threadid, service->daemon, service->logger);
            ret = 0;
        }
        else
        {
            FATAL_LOGGER(service->logger, "Initialize daemon failed, %s", strerror(errno));
            goto err;
        }
        /* acceptor */
        if(service->service_type == S_SERVICE && service->fd > 0)
        {
            if((service->acceptor = procthread_init(0)))
            {
                PROCTHREAD_SET(service, service->acceptor);
                service->acceptor->set_acceptor(service->acceptor, service->fd);
                NEW_PROCTHREAD(service, ioattr, "acceptor", 0, service->acceptor->threadid, service->acceptor, service->logger);
                ret = 0;
            }
            else
            {
                FATAL_LOGGER(service->logger, "Initialize acceptor failed, %s",  strerror(errno));
                goto err;
            }
        }
        /* tracker */ 
        if((service->tracker = procthread_init(0)))
        {
            PROCTHREAD_SET(service, service->tracker);
            service->tracker->use_cond_wait = 0;
            service->tracker->evtimer = service->etimer;
            NEW_PROCTHREAD(service, ioattr, "tracker", 0, service->tracker->threadid, service->tracker, service->logger);
            ret = 0;
        }
        else
        {
            FATAL_LOGGER(service->logger, "Initialize tracker failed, %s", strerror(errno));
            goto err;
        }
        /* initialize threads  */
        if(service->nprocthreads > SB_THREADS_MAX) service->nprocthreads = SB_THREADS_MAX;
        if(service->nprocthreads < 1) service->nprocthreads = 1;
        if(service->nprocthreads > 0)
        {
            for(i = 0; i < service->nprocthreads; i++)
            {
                if((service->procthreads[i] = procthread_init(0)))
                {
                    PROCTHREAD_SET(service, service->procthreads[i]);
                    if(service->flag & SB_USE_EVSIG)
                        procthread_set_evsig_fd(service->procthreads[i], service->cond);
                    x = i % service->niodaemons;
                    service->procthreads[i]->evbase = service->iodaemons[x]->evbase;
                    service->procthreads[i]->indaemon = service->iodaemons[x];
                    service->procthreads[i]->inqmessage = service->iodaemons[x]->message_queue;
                    if(service->outdaemon)
                    {
                        service->procthreads[i]->outevbase = service->outdaemon->evbase;
                        service->procthreads[i]->outdaemon = service->outdaemon;
                        service->procthreads[i]->outqmessage = service->outdaemon->message_queue;
                    }
                    NEW_PROCTHREAD(service, attr, "procthreads", i, service->procthreads[i]->threadid, service->procthreads[i], service->logger);
                    ret = 0;
                }
                else
                {
                    FATAL_LOGGER(service->logger, "Initialize procthreads[%d] failed, %s", i, strerror(errno));
                    goto err;
                }
            }
        }
        /* daemon worker threads */
        if(service->ndaemons > SB_THREADS_MAX) service->ndaemons = SB_THREADS_MAX;
        if(service->ndaemons > 0)
        {
            for(i = 0; i < service->ndaemons; i++)
            {
                if((service->daemons[i] = procthread_init(0)))
                {
                    PROCTHREAD_SET(service, service->daemons[i]);
                    if(service->flag & SB_USE_EVSIG)
                        procthread_set_evsig_fd(service->daemons[i], service->cond);
                    NEW_PROCTHREAD(service, attr, "daemons", i, service->daemons[i]->threadid, service->daemons[i], service->logger);
                    ret = 0;
                }
                else
                {
                    FATAL_LOGGER(service->logger, "Initialize daemons[%d] failed, %s", i, strerror(errno));
                    goto err;
                }
            }
        }
err:
        /* destroy attr */
        pthread_attr_destroy(&attr);
        pthread_attr_destroy(&ioattr);
        return ret;
#else
        service->working_mode = WORKING_PROC;
        goto running_proc;
#endif
        return ret;
    }
    return ret;
}

/* set logfile  */
int service_set_log(SERVICE *service, char *logfile)
{
    if(service && logfile)
    {
        LOGGER_INIT(service->logger, logfile);
        //DEBUG_LOGGER(service->logger, "Initialize logger %s", logfile);
        service->is_inside_logger = 1;
        return 0;
    }
    return -1;
}

/* set logfile level  */
int service_set_log_level(SERVICE *service, int level)
{
    if(service && service->logger)
    {
        LOGGER_SET_LEVEL(service->logger, level);
        return 0;
    }
    return -1;
}

/* accept handler */
int service_accept_handler(SERVICE *service, int evfd)
{
    char buf[SB_BUF_SIZE], *p = NULL, *ip = NULL;
    socklen_t rsa_len = sizeof(struct sockaddr_in);
    int fd = -1, port = -1, n = 0, opt = 1, i = 0;
    PROCTHREAD *parent = NULL, *daemon = NULL;
    struct linger linger = {0};
    struct sockaddr_in rsa;
    CONN *conn = NULL;
    void *ssl = NULL;

    if(service)
    {
        if(evfd <= 0) evfd = service->fd;
        if(service->sock_type == SOCK_STREAM)
        {
            daemon = service->daemon;
            while((fd = accept(evfd, (struct sockaddr *)&rsa, &rsa_len)) > 0)
            {
                ip = inet_ntoa(rsa.sin_addr);
                port = ntohs(rsa.sin_port);
#ifdef HAVE_SSL
                if(service->is_use_SSL && service->s_ctx)
                {
                    if((ssl = SSL_new(XSSL_CTX(service->s_ctx))) && SSL_set_fd((SSL *)ssl, fd) > 0 
                            && SSL_accept((SSL *)ssl) > 0)                                                   
                    {
                        goto new_conn;
                    }
                    else goto err_conn; 
                }
#endif
new_conn:
                if(service->flag & SB_SO_LINGER)
                {
                    linger.l_onoff = 1;linger.l_linger = 0;
                    setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger));
                }
                opt = 1;setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
                if(service->flag & SB_TCP_NODELAY)
                {
                    opt = 1;setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
                }
                if((service->flag & SB_NEWCONN_DELAY) && daemon && daemon->pushconn(daemon, fd, ssl) == 0)
                {
                    ACCESS_LOGGER(service->logger, "Accepted i:%d new-connection[%s:%d]  via %d", i, ip, port, fd);
                    i++;
                    continue;
                }
                else if((conn = service_addconn(service, service->sock_type, fd, ip, port, service->ip, service->port, &(service->session), ssl, CONN_STATUS_FREE)))
                {
                    ACCESS_LOGGER(service->logger, "Accepted i:%d new-connection[%s:%d]  via %d", i, ip, port, fd);
                    i++;
                    continue;
                }
                else
                {
                    WARN_LOGGER(service->logger, "accept newconnection[%s:%d]  via %d failed, %s", ip, port, fd, strerror(errno));

                }
err_conn:               
#ifdef HAVE_SSL
                if(ssl)
                {
                    SSL_shutdown((SSL *)ssl);
                    SSL_free((SSL *)ssl);
                    ssl = NULL;
                }
#endif
                if(fd > 0)
                {
                    shutdown(fd, SHUT_RDWR);
                    close(fd);
                }
                break;
            }
        }
        else if(service->sock_type == SOCK_DGRAM)
        {
            while((n = recvfrom(evfd, buf, SB_BUF_SIZE, 
                            0, (struct sockaddr *)&rsa, &rsa_len)) > 0)
            {
                ip = inet_ntoa(rsa.sin_addr);
                port = ntohs(rsa.sin_port);
                //linger.l_onoff = 1;linger.l_linger = 0;opt = 1;
                if((service->session.flags & SB_MULTICAST))
                {
                    ACCESS_LOGGER(service->logger, "Accepted new connection[%s:%d] ndata:%d nconns_free:%d", ip, port, n, service->nconns_free);
                    if((conn = service_getconn(service, 0)))
                    //if((conn = service->newconn(service, -1, -1, ip, port, NULL)))
                    {
                        strcpy(conn->remote_ip, ip); 
                        conn->remote_port = port;
                        p = buf;
                        MMB_PUSH(conn->buffer, p, n);
                        if((parent = (PROCTHREAD *)(conn->parent)))
                        {
                            qmessage_push(parent->message_queue, MESSAGE_BUFFER, conn->index, conn->fd, 
                                    -1, parent, conn, NULL);
                            parent->wakeup(parent);
                        }
                        i++;
                    }
                    else
                    {
                        FATAL_LOGGER(service->logger, "NONE-RESOUCE for handling connection[%s:%d]", ip, port);

                    }
                    continue;
                }
                else if((fd = socket(AF_INET, SOCK_DGRAM, 0)) > 0 
                && setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == 0
#ifdef SO_REUSEPORT
                && setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == 0
#endif
                        && bind(fd, (struct sockaddr *)&(service->sa), 
                            sizeof(struct sockaddr)) == 0
                        && connect(fd, (struct sockaddr *)&rsa, 
                            sizeof(struct sockaddr)) == 0
                        && (conn = service_addconn(service, service->sock_type, fd, 
                                ip, port, service->ip, service->port, 
                                &(service->session), NULL, CONN_STATUS_FREE)))
                {
                    i++;
                    p = buf;
                    MMB_PUSH(conn->buffer, p, n);
                    if((parent = (PROCTHREAD *)(conn->parent)))
                    {
                        qmessage_push(parent->message_queue, MESSAGE_BUFFER, conn->index, conn->fd, 
                                -1, parent, conn, NULL);
                        parent->wakeup(parent);
                    }
                    continue;
                }
                else
                {
                    FATAL_LOGGER(service->logger, "Accepted new connection[%s:%d] via %d buffer:%d failed, %s", ip, port, fd, MMB_NDATA(conn->buffer), strerror(errno));
                    shutdown(fd, SHUT_RDWR);
                    close(fd);
                    break;
                }
            }
        }
    }
    return i;
}


/* event handler */
void service_event_handler(int event_fd, int flag, void *arg)
{
    SERVICE *service = (SERVICE *)arg;
    if(service)
    {
        if(event_fd > 0 && (flag & E_READ))
        {
            service_accept_handler(service, event_fd);
        }
    }
    return ;
}
/* new connection */
CONN *service_newconn(SERVICE *service, int inet_family, int socket_type, 
        char *inet_ip, int inet_port, SESSION *session)
{
    int fd = -1, family = -1, sock_type = -1, remote_port = -1, 
        local_port = -1, flag = 0, opt = 0, status = 0;
    char *local_ip = NULL, *remote_ip = NULL;
    struct sockaddr_in rsa, lsa;
    socklen_t lsa_len = sizeof(lsa);
    struct linger linger = {0};
    SESSION *sess = NULL;
    CONN *conn = NULL;
    void *ssl = NULL;

    if(service && service->lock == 0)
    {
        family  = (inet_family > 0 ) ? inet_family : service->family;
        sock_type = (socket_type > 0 ) ? socket_type : service->sock_type;
        remote_ip = (inet_ip) ? inet_ip : service->ip;
        remote_port  = (inet_port > 0 ) ? inet_port : service->port;
        sess = (session) ? session : &(service->session);
        if((fd = socket(family, sock_type, 0)) > 0)
        {
            //DEBUG_LOGGER(service->logger, "new_conn[%s:%d] via %d", remote_ip, remote_port, fd);
            rsa.sin_family = family;
            rsa.sin_addr.s_addr = inet_addr(remote_ip);
            rsa.sin_port = htons(remote_port);
#ifdef HAVE_SSL
            if((sess->flags & SB_USE_SSL) &&  sock_type == SOCK_STREAM && service->c_ctx)
            {
                if((ssl = SSL_new(XSSL_CTX(service->c_ctx))) 
                        && connect(fd, (struct sockaddr *)&rsa, sizeof(rsa)) == 0 
                        && SSL_set_fd((SSL *)ssl, fd) > 0 && SSL_connect((SSL *)ssl) >= 0)
                {
                    goto new_conn;
                }
                else goto err_conn;
            }
#endif
            if(service->flag & SB_SO_LINGER)
            {
                linger.l_onoff = 1;linger.l_linger = 0;
                setsockopt(fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(struct linger));
            }
            opt = 1;setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
            if(service->flag & SB_TCP_NODELAY)
            {
                //opt = 60;setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &opt, sizeof(opt));
                //opt = 5;setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &opt, sizeof(opt));
                //opt = 3;setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &opt, sizeof(opt)); 
                opt = 1;setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
            }
            if(sess)
            {
                if(sess->flags & SB_MULTICAST)
                {
                    unsigned char op = (unsigned char)sess->multicast_ttl;
                    if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == 0
#ifdef SO_REUSEPORT
                    && setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) == 0
#endif
                    )
                    {
                        if(inet_ip && inet_port > 0 
                        && bind(fd, (struct sockaddr *)&(service->sa), sizeof(struct sockaddr)) == 0)
                        {
                            if(op > 0)setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &op, sizeof(op));
                            //op = 0;setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &op, sizeof(op));
                            if(connect(fd, (struct sockaddr *)&rsa, sizeof(rsa)) != 0)
                                goto err_conn;
                        }
                        goto new_conn;
                    }
                    goto err_conn;
                }
                else
                {
                    if((sess->flags & SB_NONBLOCK))
                    {
                        flag = fcntl(fd, F_GETFL, 0)|O_NONBLOCK;
                        if(fcntl(fd, F_SETFL, flag) != 0) goto err_conn;
                        if((connect(fd, (struct sockaddr *)&rsa, sizeof(rsa)) == 0 
                                    || errno == EINPROGRESS))
                        {
                            goto new_conn;
                        }
                        else 
                            goto err_conn;
                    }
                    else
                    {
                        if(connect(fd, (struct sockaddr *)&rsa, sizeof(rsa)) == 0)
                            goto new_conn;
                        else goto err_conn;
                    }
                }
            }
new_conn:
            getsockname(fd, (struct sockaddr *)&lsa, &lsa_len);
            local_ip    = inet_ntoa(lsa.sin_addr);
            local_port  = ntohs(lsa.sin_port);
            status = CONN_STATUS_FREE;
            if(flag != 0) status = CONN_STATUS_READY; 
            if((conn = service_addconn(service, sock_type, fd, remote_ip, 
                    remote_port, local_ip, local_port, sess, ssl, status)))
            {
                return conn;
            }
err_conn:
#ifdef HAVE_SSL
            if(ssl)
            {
                SSL_shutdown((SSL *)ssl);
                SSL_free((SSL *)ssl);
                ssl = NULL;
            }
#endif
            if(fd > 0)
            {
                shutdown(fd, SHUT_RDWR);
                close(fd);
            }
            return conn;
        }
        else
        {
            FATAL_LOGGER(service->logger, "socket(%d, %d, 0) failed, %s", family, sock_type, strerror(errno));
        }
    }
    return conn;
}

/* new connection */
CONN *service_newproxy(SERVICE *service, CONN *parent, int inet_family, int socket_type, 
        char *inet_ip, int inet_port, SESSION *session)
{
    CONN *conn = NULL;
    struct sockaddr_in rsa, lsa;
    socklen_t lsa_len = sizeof(lsa);
    int fd = -1, family = -1, sock_type = -1, remote_port = -1, local_port = -1;
    char *local_ip = NULL, *remote_ip = NULL;
    SESSION *sess = NULL;
    void *ssl = NULL;

    if(service && service->lock == 0 && parent)
    {
        if(parent && (conn = parent->session.child))
        {
            conn->session.parent = NULL;
            conn->over(conn);
            conn = NULL;
        }
        family  = (inet_family > 0 ) ? inet_family : service->family;
        sock_type = (socket_type > 0 ) ? socket_type : service->sock_type;
        remote_ip = (inet_ip) ? inet_ip : service->ip;
        remote_port  = (inet_port > 0 ) ? inet_port : service->port;
        sess = (session) ? session : &(service->session);
        rsa.sin_family = family;
        rsa.sin_addr.s_addr = inet_addr(remote_ip);
        rsa.sin_port = htons(remote_port);
        if((fd = socket(family, sock_type, 0)) > 0
                && connect(fd, (struct sockaddr *)&rsa, sizeof(rsa)) == 0)
        {
#ifdef HAVE_SSL
            if((sess->flags & SB_USE_SSL) && sock_type == SOCK_STREAM && service->c_ctx)
            {
                //DEBUG_LOGGER(service->logger, "SSL_newproxy() to %s:%d",remote_ip, remote_port);
                if((ssl = SSL_new(XSSL_CTX(service->c_ctx))) 
                        && SSL_set_fd((SSL *)ssl, fd) > 0 && SSL_connect((SSL *)ssl) >= 0)
                {
                    goto new_conn;
                }
                else goto err_conn;
            }
#endif
new_conn:
            getsockname(fd, (struct sockaddr *)&lsa, &lsa_len);
            local_ip    = inet_ntoa(lsa.sin_addr);
            local_port  = ntohs(lsa.sin_port);
            if(parent->session.timeout == 0)
                parent->session.timeout = SB_PROXY_TIMEOUT;
            parent->session.packet_type |= PACKET_PROXY;
            sess->packet_type |= PACKET_PROXY;
            sess->parent = parent;
            sess->parentid = parent->index;
            sess->timeout = SB_PROXY_TIMEOUT;;
            if((conn = service_addconn(service, sock_type, fd, remote_ip, remote_port, 
                            local_ip, local_port, sess, ssl, CONN_STATUS_FREE)))
            {
                return conn;
            }
err_conn:
#ifdef HAVE_SSL
            if(ssl)
            {
                SSL_shutdown((SSL *)ssl);
                SSL_free((SSL *)ssl);
                ssl = NULL;
            }
#endif
            if(fd > 0)
            {
                shutdown(fd, SHUT_RDWR);
                close(fd);
            }
            return conn;
        }
        else
        {
            FATAL_LOGGER(service->logger, "connect to %s:%d via %d session[%p] failed, %s",remote_ip, remote_port, fd, sess, strerror(errno));
        }
    }
    return conn;
}


/* add new connection */
CONN *service_addconn(SERVICE *service, int sock_type, int fd, char *remote_ip, int remote_port, 
        char *local_ip, int local_port, SESSION *session, void *ssl, int status)
{
    PROCTHREAD *procthread = NULL;
    CONN *conn = NULL;
    int index = 0;

    if(service && service->lock == 0 && fd > 0 && session)
    {
        if((conn = service_popfromq(service)))
        {
            conn->fd = fd;
            conn->ssl = ssl;
            conn->status = status;
            strcpy(conn->remote_ip, remote_ip);
            conn->remote_port = remote_port;
            strcpy(conn->local_ip, local_ip);
            conn->local_port = local_port;
            conn->sock_type = sock_type;
            conn->evtimer   = service->evtimer;
            conn->logger    = service->logger;
            conn->groupid   = session->groupid;
            conn->set_session(conn, session);
            /* add  to procthread */
            if(service->working_mode == WORKING_PROC)
            {
                if(service->daemon)
                {
                    service->daemon->add_connection(service->daemon, conn);
                }
                else
                {
                    FATAL_LOGGER(service->logger, "can not add connection[%s:%d] on %s:%d via %d  to service[%s]", remote_ip, remote_port, local_ip, local_port, fd, service->service_name);
                    service_pushtoq(service, conn);
                }
            }
            else if(service->working_mode == WORKING_THREAD && service->nprocthreads > 0)
            {
                ACCESS_LOGGER(service->logger, "adding connection[%p][%s:%d] local[%s:%d] dstate:%d via %d", conn, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->d_state, conn->fd);
                index = fd % service->nprocthreads;
                if(service->procthreads && (procthread = service->procthreads[index])) 
                {
                    if(status == CONN_STATUS_FREE)
                    {
                        procthread->add_connection(procthread, conn);   
                    }
                    else
                    {
                        procthread->addconn(procthread, conn);
                    }
                }
                else
                {
                    //FATAL_LOGGER(service->logger, "can not add connection remote[%s:%d]-local[%s:%d] via %d  to service[%s]->procthreads[%p][%d] nprocthreads:%d", remote_ip, remote_port, local_ip, local_port, fd, service->service_name, service->procthreads, index, service->nprocthreads);
                    service_pushtoq(service, conn);
                }
            }
            else
            {
                    service_pushtoq(service, conn);
            }
        }
    }
    return conn;
}

/* push connection to connections pool */
int service_pushconn(SERVICE *service, CONN *conn)
{
    int ret = -1, x = 0, id = 0, i = 0;
    CONN *parent = NULL;

    if(service && service->lock == 0 && conn)
    {
        MUTEX_LOCK(service->mutex);
        for(i = 1; i < service->connections_limit; i++)
        {
            if(service->connections[i] == NULL)
            {
                service->connections[i] = conn;
                conn->index = i;
                service->running_connections++;
                if((id = conn->groupid) > 0 && id < SB_GROUPS_MAX)
                {
                    x = 0;
                    while(x < SB_GROUP_CONN_MAX)
                    {
                        if(service->groups[id].conns_free[x] == 0)
                        {
                            service->groups[id].conns_free[x] = i;
                            ++(service->groups[id].nconns_free);
                            if(conn->status == CONN_STATUS_FREE)
                            {
                                ++(service->groups[id].nconnected);
                            }
                            conn->gindex = x;
                            DEBUG_LOGGER(service->logger, "added conn[%s:%d] remote[%s:%d] via %d to groups[%d][%d] free:%d", conn->local_ip, conn->local_port, conn->remote_ip, conn->remote_port, conn->fd, id, x, service->groups[id].nconns_free);
                            break;
                        }
                        ++x;
                    }
                }
                else
                {
                    if(service->service_type == C_SERVICE || (service->session.flags & SB_MULTICAST))
                    {
                        x = 0;
                        while(x < service->conns_limit)
                        {
                            if(service->conns_free[x] == 0)
                            {
                                service->conns_free[x] = i;
                                ++(service->nconns_free);
                                conn->xindex = x;
                                break;
                            }
                            ++x;
                        }
                    }
                }
                if(i > service->index_max) service->index_max = i;
                ret = 0;
                //DEBUG_LOGGER(service->logger, "Added new conn[%p][%s:%d] on %s:%d via %d d_state:%d index[%d] of total %d", conn, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, conn->d_state,conn->index, service->running_connections);
                break;
            }
        }
        //for proxy
        if((conn->session.packet_type & PACKET_PROXY)
                && (parent = (CONN *)(conn->session.parent)) 
                && conn->session.parentid  > 0 
                && conn->session.parentid <= service->index_max 
                && conn->session.parent == service->connections[conn->session.parentid])
        {
            //DEBUG_LOGGER(service->logger, "proxy conn[%p][%s:%d] on %s:%d via %d on parent:%d", conn, conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, conn->session.parent);
            parent->bind_proxy(parent, conn);
        }
        MUTEX_UNLOCK(service->mutex);
    }
    return ret;
}

/* pop connection from connections pool with index */
int service_popconn(SERVICE *service, CONN *conn)
{
    int ret = -1, id = 0, x = 0;

    if(service && service->lock == 0 && service->connections && conn)
    {
        MUTEX_LOCK(service->mutex);
        if(conn->index > 0 && conn->index <= service->index_max
                && service->connections[conn->index] == conn)
        {
            if((id = conn->groupid) > 0 && id < SB_GROUPS_MAX)
            {
                if((x = conn->gindex) >= 0 && x < SB_CONN_MAX 
                        && service->groups[id].conns_free[x] > 0
                        && service->groups[id].conns_free[x] == conn->index)
                {
                    service->groups[id].conns_free[x] = 0;
                    --(service->groups[id].nconns_free);
                }
                if(conn->status == CONN_STATUS_FREE)
                {
                    --(service->groups[id].nconnected);
                }
                --(service->groups[id].total);
            }
            else
            {
                if(service->service_type == C_SERVICE || (service->session.flags & SB_MULTICAST))
                {
                    if((x = conn->xindex) >= 0 && x < service->conns_limit
                            && service->conns_free[x] > 0 
                            && service->conns_free[x] == conn->index)
                    {
                        service->conns_free[x] = 0;
                        --(service->nconns_free);
                        --(service->nconnections);
                    }
                }
            }
            service->connections[conn->index] = NULL;
            service->running_connections--;
            if(service->index_max == conn->index) service->index_max--;
            //DEBUG_LOGGER(service->logger, "Removed connection[%s:%d] on %s:%d via %d index[%d] of total %d", conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, conn->index, service->running_connections);
            ret = 0;
        }
        else
        {
            FATAL_LOGGER(service->logger, "Removed connection[%s:%d] on %s:%d via %d index[%d] of total %d failed", conn->remote_ip, conn->remote_port, conn->local_ip, conn->local_port, conn->fd, conn->index, service->running_connections);
        }
        MUTEX_UNLOCK(service->mutex);
        //return service_pushtoq(service, conn);
    }
    return ret;
}

/* set connection status ok */
int service_okconn(SERVICE *service, CONN *conn)
{
    int id = -1;

    if(service && conn)
    {
        if((id = conn->groupid) > 0 && id <= service->ngroups)
        {
            service->groups[id].nconnected++;
        }
        conn->status = CONN_STATUS_FREE;
        return 0;
    }
    return -1;
}

/* get connection with free state */
CONN *service_getconn(SERVICE *service, int groupid)
{
    CONN *conn = NULL;
    int i = 0, x = 0;

    if(service && service->lock == 0)
    {
        MUTEX_LOCK(service->mutex);
        if(groupid > 0 && groupid <= service->ngroups)
        {
            x = 0;
            while(x < SB_GROUP_CONN_MAX && service->groups[groupid].nconns_free > 0)
            {
                if((i = service->groups[groupid].conns_free[x]) > 0 
                        && (conn = service->connections[i]))
                {
                    if(conn->status == CONN_STATUS_FREE && conn->d_state == D_STATE_FREE 
                            && conn->c_state == C_STATE_FREE)
                    {
                        conn->gindex = -1;
                        service->groups[groupid].conns_free[x] = 0;
                        --(service->groups[groupid].nconns_free);
                        conn->start_cstate(conn);
                        break;
                    }
                    else 
                    {
                        conn = NULL;
                    }
                }
                ++x;
            }
            //MUTEX_UNLOCK(service->groups[groupid].mutex);
        }
        else
        {
            x = 0;
            while(x < service->conns_limit && service->nconns_free > 0)
            {
                if((i = service->conns_free[x]) > 0 
                        && (conn = service->connections[i]))
                {
                    if(conn->status == CONN_STATUS_FREE && conn->d_state == D_STATE_FREE 
                            && conn->c_state == C_STATE_FREE)
                    {
                        conn->xindex = -1;
                        service->conns_free[x] = 0;
                        --(service->nconns_free);
                        conn->start_cstate(conn);
                        break;
                    }
                    else 
                    {
                        conn = NULL;
                    }
                }
                ++x;
            }
        }
        MUTEX_UNLOCK(service->mutex);
    }
    return conn;
}

/* freeconn */
int service_freeconn(SERVICE *service, CONN *conn)
{
    int id = 0, x = 0;

    if(service && conn)
    {
        MUTEX_LOCK(service->mutex);
        if((id = conn->groupid) > 0 && id < SB_GROUPS_MAX)
        {
            if(service->groups[id].limit <= 0)
            {
                conn->close(conn);
            }
            else
            {
                x = 0;
                while(x < SB_GROUP_CONN_MAX)
                {
                    if(service->groups[id].conns_free[x] == 0)
                    {
                        service->groups[id].conns_free[x] = conn->index;
                        ++(service->groups[id].nconns_free);
                        conn->gindex = x;
                        conn->over_cstate(conn);
                        break;
                    }
                    ++x;
                }
            }
        }
        else
        {
            if(service->nconns_free < service->conns_limit)
            {
                x = 0;
                while(x < service->conns_limit)
                {
                    if(service->conns_free[x] == 0)
                    {
                        service->nconns_free++;
                        service->conns_free[x] = conn->index;
                        conn->xindex = x;
                        conn->over_cstate(conn);
                        break;
                    }
                    ++x;
                }
            }
            else
            {
                conn->close(conn);
            }
        }
        MUTEX_UNLOCK(service->mutex);
        return 0;
    }
    return -1;
}

/* find connection as index */
CONN *service_findconn(SERVICE *service, int index)
{
    CONN *conn = NULL;
    if(service && service->lock == 0)
    {
        MUTEX_LOCK(service->mutex);
        if(index > 0 && index <= service->index_max)
        {
            if((conn = service->connections[index]) && (conn->s_state & D_STATE_CLOSE))
                conn = NULL;
        }
        MUTEX_UNLOCK(service->mutex);
    }
    return conn;
}

/* service over conn */
void service_overconn(SERVICE *service, CONN *conn)
{
    PROCTHREAD *daemon = NULL;

    if(service && conn)
    {
        if((daemon = service->daemon))
        {
            qmessage_push(daemon->message_queue, MESSAGE_QUIT, conn->index, conn->fd, 
                    -1, daemon, conn, NULL);
            daemon->wakeup(daemon);
        }
    }
    return ;
}

/* push to qconns */
int service_pushtoq(SERVICE *service, CONN *conn)
{
    int x = 0;

    if(service && conn)
    {
        MUTEX_LOCK(service->mutex);
        if((x = service->nqconns) < SB_QCONN_MAX)
        {
            service->qconns[service->nqconns++] = conn;
        }
        else 
        {
            x = -1;
            service->nconn--;
        }
        MUTEX_UNLOCK(service->mutex);
        if(x == -1) conn->clean(conn);
    }
    return x;
}

/* push to qconn */
CONN *service_popfromq(SERVICE *service)
{
    CONN *conn = NULL;
    int x = 0;

    if(service)
    {
        MUTEX_LOCK(service->mutex);
        if(service->nqconns > 0 && (x = --(service->nqconns)) >= 0 
                && (conn = service->qconns[x]))
        {
            service->qconns[x] = NULL;
        }
        else
        {
            x = -1;
            service->nconn++;
        }
        MUTEX_UNLOCK(service->mutex);
        if(x == -1)conn = conn_init();
    }
    return conn;
}

/* pop chunk from service  */
/*
CHUNK *service_popchunk(SERVICE *service)
{
    CHUNK *cp = NULL;
    int x = 0;

    if(service && service->lock == 0 && service->qchunks)
    {
        ACCESS_LOGGER(service->logger, "nqchunks:%d", service->nqchunks);
        MUTEX_LOCK(service->mutex);
        if(service->nqchunks > 0 && (x = --(service->nqchunks)) >= 0 
                && (cp = service->qchunks[x]))
        {
            service->qchunks[x] = NULL;
        }
        else
        {
            x = -1;
            service->nchunks++;
        }
        MUTEX_UNLOCK(service->mutex);
        ACCESS_LOGGER(service->logger, "nqchunks:%d", service->nqchunks);
        if(x == -1) 
            cp = chunk_init();
    }
    return cp;
}
*/
/* push chunk to service  */
/*
int service_pushchunk(SERVICE *service, CHUNK *cp)
{
    int ret = -1, x = 0;

    if(service && service->lock == 0 && service->qchunks && cp)
    {
        ACCESS_LOGGER(service->logger, "nqchunks:%d", service->nqchunks);
        chunk_reset(cp);
        ACCESS_LOGGER(service->logger, "nqchunks:%d", service->nqchunks);
        MUTEX_LOCK(service->mutex);
        if(service->nqchunks < SB_CHUNKS_MAX)
        {
            x = service->nqchunks++;
            service->qchunks[x] = cp;
        }
        else 
        {
            x = -1;
            service->nchunks--;
        }
        MUTEX_UNLOCK(service->mutex);
        ACCESS_LOGGER(service->logger, "nqchunks:%d", service->nqchunks);
        if(x == -1) chunk_clean(cp);
        ret = 0;
    }
    return ret;
}
*/
/* new chunk */
/*
CB_DATA *service_newchunk(SERVICE *service, int len)
{
    CB_DATA *chunk = NULL;
    CHUNK *cp = NULL;

    if(service && service->lock == 0)
    {
        if((cp = service_popchunk(service)))
        {
            chunk_mem(cp, len);
            chunk = (CB_DATA *)cp;
        }
    }
    return chunk;
}
*/
/* new chunk and memset */
/*
CB_DATA *service_mnewchunk(SERVICE *service, int len)
{
    CB_DATA *chunk = NULL;
    CHUNK *cp = NULL;

    if(service && service->lock == 0)
    {
        if((cp = service_popchunk(service)))
        {
            chunk_mem(cp, len);
            if(cp->data) memset(cp->data, 0, len);
            chunk = (CB_DATA *)cp;
        }
    }
    return chunk;
}
*/
/* set service session */
int service_set_session(SERVICE *service, SESSION *session)
{
    if(service && session)
    {
        memcpy(&(service->session), session, sizeof(SESSION));
        return 0;
    }
    return -1;
}

/* add multicast */
int service_new_multicast(SERVICE *service, char *multicast_ip)
{
    int ret = -1, i = 0, fd = 0, op = 0;
    struct ip_mreq mreq;

    if(service && service->lock == 0 && service->sock_type == SOCK_DGRAM 
            && multicast_ip && service->ip 
            && (service->session.flags & SB_MULTICAST_LIST))
    {
        MUTEX_LOCK(service->mutex);
        if((i = service->nmulticasts) < SB_MULTICAST_MAX)
        {
            fd = service->multicasts[i];
            service->nmulticasts++;
        }
        MUTEX_UNLOCK(service->mutex);
        memset(&mreq, 0, sizeof(struct ip_mreq));
        mreq.imr_multiaddr.s_addr = inet_addr(multicast_ip);
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &op, sizeof(op));
        if(fd > 0 && (ret = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
                        (char*)&mreq, sizeof(struct ip_mreq))) == 0)
        {
            DEBUG_LOGGER(service->logger, "added new multicast:%s to service[%p]->fd[%d]",multicast_ip, service, service->fd);
        }
        else
        {
            WARN_LOGGER(service->logger, "adding multicast:%s to multicast_fd[%d] failed, %s",multicast_ip, fd, strerror(errno));
        }
    }
    return ret;
}

/* set multicast */
int service_add_multicast(SERVICE *service, char *multicast_ip)
{
    struct ip_mreq mreq;
    int ret = -1, op = 0;

    if(service && service->lock == 0 && service->sock_type == SOCK_DGRAM && multicast_ip 
            && service->ip && service->fd > 0)
    {
        memset(&mreq, 0, sizeof(struct ip_mreq));
        mreq.imr_multiaddr.s_addr = inet_addr(multicast_ip);
        mreq.imr_interface.s_addr = htonl(INADDR_ANY);
        setsockopt(service->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &op, sizeof(op));
        if((ret = setsockopt(service->fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, 
                        (char*)&mreq, sizeof(struct ip_mreq))) == 0)
        {
            DEBUG_LOGGER(service->logger, "added multicast:%s to service[%p]->fd[%d]",multicast_ip, service, service->fd);
        }
        else
        {
            WARN_LOGGER(service->logger, "added multicast:%s to service[%p]->fd[%d] failed, %s",multicast_ip, service, service->fd, strerror(errno));
        }
    }
    return ret;
}

/* drop multicast */
int service_drop_multicast(SERVICE *service, char *multicast_ip)
{
    struct ip_mreq mreq;
    int ret = -1;

    if(service && service->sock_type == SOCK_DGRAM && service->ip && service->fd > 0)
    {
        memset(&mreq, 0, sizeof(struct ip_mreq));
        mreq.imr_multiaddr.s_addr = inet_addr(multicast_ip);
        mreq.imr_interface.s_addr = inet_addr(service->ip);
        ret = setsockopt(service->fd, IPPROTO_IP, IP_DROP_MEMBERSHIP,(char*)&mreq, sizeof(mreq));
    }
    return ret;
}

/* broadcast */
int service_broadcast(SERVICE *service, char *data, int len)
{
    int ret = -1, i = 0;
    CONN *conn = NULL;

    if(service && service->lock == 0 && service->running_connections > 0)
    {
        for(i = 1; i < service->index_max; i++)
        {
            if((conn = service->connections[i]))
            {
                conn->push_chunk(conn, data, len);
            }
        }
        ret = 0;
    }
    return ret;
}

/* add group */
int service_addgroup(SERVICE *service, char *ip, int port, int limit, SESSION *session)
{
    int id = -1;
    if(service && service->lock == 0 && service->ngroups < SB_GROUPS_MAX)
    {
        MUTEX_LOCK(service->mutex);
        id = ++(service->ngroups);
        strcpy(service->groups[id].ip, ip);
        service->groups[id].port = port;
        service->groups[id].limit = limit;
        //MUTEX_INIT(service->groups[id].mutex);
        memcpy(&(service->groups[id].session), session, sizeof(SESSION));
        MUTEX_UNLOCK(service->mutex);
        //fprintf(stdout, "%s::%d service[%s]->group[%d]->session.data_handler:%p\n", __FILE__, __LINE__, service->service_name, id, service->groups[id].session.data_handler);
    }
    return id;
}

/* add group */
int service_closegroup(SERVICE *service, int groupid)
{
    int i = 0, id = -1;
    CONN *conn = NULL;

    if(service && groupid < SB_GROUPS_MAX)
    {
        MUTEX_LOCK(service->mutex);
        service->groups[groupid].limit = 0;
        while((i = --(service->groups[groupid].nconns_free)) >= 0)
        {
            if((id = service->groups[groupid].conns_free[i]) >= 0
                && (conn = service->connections[id]))
            {
                conn->close(conn);
            }
        }
        MUTEX_UNLOCK(service->mutex);
    }
    return id;
}

/* group cast */
int service_castgroup(SERVICE *service, char *data, int len)
{
    CONN *conn = NULL;
    int i = 0;

    if(service && service->lock == 0 && data && len > 0 && service->ngroups > 0)
    {
        for(i = 1; i <= service->ngroups; i++)
        {
            if((conn = service_getconn(service, i)))
            {
                conn->start_cstate(conn);
                conn->groupid = i;
                conn->push_chunk(conn, data, len);
            }
        }
        return 0;
    }
    return -1;
}

/* state groups */
int service_stategroup(SERVICE *service)
{
    CONN *conn = NULL;
    SESSION session = {0};
    int i = 0;

    if(service && service->lock == 0 && service->ngroups > 0)
    {
        for(i = 1; i <= service->ngroups; i++)
        {
            if(service->groups[i].total >= service->groups[i].limit && service->groups[i].nconnected <= 0) 
            {
                //DEBUG_LOGGER(service->logger, "ignore stategroup(%d) total:%d nconnected:%d limit:%d", i, service->groups[i].total, service->groups[i].nconnected, service->groups[i].limit);
                continue;
            }
            //DEBUG_LOGGER(service->logger, "stategroup(%d) total:%d nconnected:%d limit:%d", i, service->groups[i].total, service->groups[i].nconnected, service->groups[i].limit);
            memcpy(&session, &(service->groups[i].session), sizeof(SESSION));
            session.groupid = i;
            while(service->groups[i].limit > 0  
                    && service->groups[i].total < service->groups[i].limit
                    && (conn = service_newconn(service, -1, -1, service->groups[i].ip,
                            service->groups[i].port, &session)))
            {
                //conn->groupid = i;
                service->groups[i].total++;
                if(service->groups[i].nconnected <= 0) break;
            }
        }
        //DEBUG_LOGGER(service->logger, "over stategroup()");
        return 0;
    }
    return -1;
}

/* new task */
int service_newtask(SERVICE *service, CALLBACK *task_handler, void *arg)
{
    PROCTHREAD *pth = NULL;
    int index = 0, ret = -1;

    if(service && service->lock == 0)
    {
        /* Add task for procthread */
        if(service->working_mode == WORKING_PROC)
            pth = service->daemon;
        else if(service->working_mode == WORKING_THREAD && service->ndaemons > 0)
        {
            index = service->ntask % service->ndaemons;
            pth = service->daemons[index];
        }
        if(pth)
        {
            pth->newtask(pth, task_handler, arg);
            service->ntask++;
            ret = 0;
        }
    }
    return ret;
}

/* add new transaction */
int service_newtransaction(SERVICE *service, CONN *conn, int tid)
{
    PROCTHREAD *pth = NULL;
    int index = 0, ret = -1;

    if(service && service->lock == 0 && conn && conn->fd > 0)
    {
        /* Add transaction for procthread */
        if(service->working_mode == WORKING_PROC && service->daemon)
        {
            return service->daemon->newtransaction(service->daemon, conn, tid);
        }
        /* Add transaction to procthread pool */
        if(service->working_mode == WORKING_THREAD && service->nprocthreads > 0)
        {
            index = conn->fd % service->nprocthreads;
            pth = service->procthreads[index];
            if(pth && pth->newtransaction)
                return pth->newtransaction(pth, conn, tid);
        }
    }
    return ret;
}

/* stop service */
void service_stop(SERVICE *service)
{
    CONN *conn = NULL;
    int i = 0;

    if(service)
    {
        service->lock = 1;
        //acceptor
        if(service->acceptor)
        {
            service->acceptor->stop(service->acceptor);
            ACCESS_LOGGER(service->logger, "Ready for stop threads[acceptor]");
            if(service->fd > 0){shutdown(service->fd, SHUT_RDWR);close(service->fd); service->fd = -1;}
            PROCTHREAD_EXIT(service->acceptor->threadid, NULL);
        }
        else
        {
            if(service->fd > 0){shutdown(service->fd, SHUT_RDWR);close(service->fd); service->fd = -1;}
        }
        if(service->session.flags & SB_MULTICAST_LIST)
        {
            for(i = 0; i < SB_MULTICAST_MAX; i++)
            {
                shutdown(service->multicasts[i], SHUT_RDWR);
                close(service->multicasts[i]);
                service->multicasts[i] = 0;
            }
        }
        //stop all connections 
        if(service->connections && service->index_max > 0)
        {
            ACCESS_LOGGER(service->logger, "Ready for close connections[%d]",  service->index_max);
            MUTEX_LOCK(service->mutex);
            for(i = 1; i <= service->index_max; i++)
            {
                if((conn = service->connections[i]))
                {
                    conn->close(conn);
                }
            }
            MUTEX_UNLOCK(service->mutex);
        }
        //iodaemons
        if(service->niodaemons > 0)
        {
            ACCESS_LOGGER(service->logger, "Ready for stop iodaemons:%d", service->niodaemons);
            for(i = 0; i < service->niodaemons; i++)
            {
                if(service->iodaemons[i])
                {
                    service->iodaemons[i]->stop(service->iodaemons[i]);
                    PROCTHREAD_EXIT(service->iodaemons[i]->threadid, NULL);
                }
            }
        }
        //outdaemon
        if(service->outdaemon)
        {
            ACCESS_LOGGER(service->logger, "Ready for stop threads[outdaemon]");
            service->outdaemon->stop(service->outdaemon);
            if(service->working_mode == WORKING_THREAD)
            {
                PROCTHREAD_EXIT(service->outdaemon->threadid, NULL);
            }
        }
        //threads
        if(service->nprocthreads > 0)
        {
            ACCESS_LOGGER(service->logger, "Ready for stop procthreads");
            for(i = 0; i < service->nprocthreads; i++)
            {
                if(service->procthreads[i])
                {
                    service->procthreads[i]->stop(service->procthreads[i]);
                    PROCTHREAD_EXIT(service->procthreads[i]->threadid, NULL);
                }
            }
        }
        //daemons
        if(service->ndaemons > 0)
        {
            ACCESS_LOGGER(service->logger, "Ready for stop daemons");
            for(i = 0; i < service->ndaemons; i++)
            {
                if(service->daemons[i])
                {
                    service->daemons[i]->stop(service->daemons[i]);
                    PROCTHREAD_EXIT(service->daemons[i]->threadid, NULL);
                }
            }
            //DEBUG_LOGGER(service->logger, "over for stop daemons");
        }
        //daemon
        if(service->daemon)
        {
            ACCESS_LOGGER(service->logger, "Ready for stop threads[daemon]");
            service->daemon->stop(service->daemon);
            if(service->working_mode == WORKING_THREAD)
            {
                PROCTHREAD_EXIT(service->daemon->threadid, NULL);
            }
        }
        /* delete evtimer */
        EVTIMER_DEL(service->evtimer, service->evid);
        /*tracker */
        if(service->tracker)
        {
            ACCESS_LOGGER(service->logger, "Ready for stop threads[tracker]");
            service->tracker->stop(service->tracker);
            if(service->working_mode == WORKING_THREAD)
            {
                PROCTHREAD_EXIT(service->tracker->threadid, NULL);
            }
        }
        /*remove event */
        event_destroy(&(service->event));
        if(service->session.flags & SB_MULTICAST_LIST)
        {
            for(i = 0; i < SB_MULTICAST_MAX; i++)
            {
                event_destroy(&(service->evmulticasts[i]));
            }
        }
        ACCESS_LOGGER(service->logger, "over for stop service[%s]", service->service_name);
    }
    return ;
}

/* state check */
void service_state(void *arg)
{
    SERVICE *service = (SERVICE *)arg;
    int n = 0;

    if(service)
    {
        if(service->service_type == C_SERVICE || (service->session.flags & SB_MULTICAST))
        {
            if(service->ngroups > 0)service_stategroup(service);
            if(service->nconnections < service->conns_limit)
            {
                //DEBUG_LOGGER(service->logger, "Ready for state connection[%s:%d][%d] running:%d ",service->ip, service->port, service->conns_limit,service->running_connections);
                n = service->conns_limit - service->nconnections;
                while(n > 0)
                {
                    if(service->newconn(service, -1, -1, NULL, -1, NULL) == NULL)
                    {
                        //FATAL_LOGGER(service->logger, "connect to %s:%d failed, %s", service->ip, service->port, strerror(errno));
                        break;
                    }
                    else
                    {
                        service->nconnections++;
                    }
                    n--;
                }
            }
        }
    }
    return ;
}

/* heartbeat handler */
void service_set_heartbeat(SERVICE *service, int interval, CALLBACK *handler, void *arg)
{
    if(service)
    {
        service->heartbeat_interval = interval;
        service->heartbeat_handler = handler;
        service->heartbeat_arg = arg;
    }
    return ;
}

/* active heartbeat */
void service_active_heartbeat(void *arg)
{
    SERVICE *service = (SERVICE *)arg;

    if(service)
    {
        service_state(service);
        if(service->heartbeat_handler)
        {
            service->heartbeat_handler(service->heartbeat_arg);
        }
        EVTIMER_UPDATE(service->evtimer, service->evid, service->heartbeat_interval, 
                &service_evtimer_handler, (void *)service);
    }
    return ;
}

/* active evtimer heartbeat */
void service_evtimer_handler(void *arg)
{
    SERVICE *service = (SERVICE *)arg;

    if(service)
    {
        service_active_heartbeat(arg);
    }
    return ;
}

/* service clean */
void service_clean(SERVICE *service)
{
    CONN *conn = NULL;
    //CHUNK *cp = NULL;
    int i = 0;

    if(service)
    {
        event_clean(&(service->event)); 
        if(service->session.flags & SB_MULTICAST_LIST)
        {
            for(i = 0; i < SB_MULTICAST_MAX; i++)
            {
                event_clean(&(service->evmulticasts[i]));
            }
        }
        if(service->daemon) service->daemon->clean(service->daemon);
        if(service->acceptor) service->acceptor->clean(service->acceptor);
        if(service->etimer) {EVTIMER_CLEAN(service->etimer);}
        if(service->outdaemon) service->outdaemon->clean(service->outdaemon);
        if(service->tracker) service->tracker->clean(service->tracker);
        if(service->niodaemons > 0)
        {
            for(i = 0; i < service->ndaemons; i++)
            {
                if(service->iodaemons[i])
                    service->iodaemons[i]->clean(service->iodaemons[i]);
            }
        }
        //clean procthreads
        if(service->nprocthreads > 0)
        {
            for(i = 0; i < service->nprocthreads; i++)
            {
                if(service->procthreads[i])
                    service->procthreads[i]->clean(service->procthreads[i]);
            }
        }
        //clean daemons
        if(service->ndaemons > 0)
        {
            for(i = 0; i < service->ndaemons; i++)
            {
                if(service->daemons[i])
                {
                    service->daemons[i]->clean(service->daemons[i]);
                }
            }
        }
        //clean connection_queue
        if(service->nqconns > 0)
        {
            while((i = --(service->nqconns)) >= 0)
            {
                if((conn = (service->qconns[i]))) 
                {
                    conn->clean(conn);
                    service->nconn--;
                }
            }
        }
        /* SSL */
#ifdef HAVE_SSL
        if(service->s_ctx) SSL_CTX_free(XSSL_CTX(service->s_ctx));
        if(service->c_ctx) SSL_CTX_free(XSSL_CTX(service->c_ctx));
#endif
        MUTEX_DESTROY(service->mutex);
        if(service->is_inside_logger) 
        {
            LOGGER_CLEAN(service->logger);
        }
        xmm_free(service, sizeof(SERVICE));
    }
    return ;
}

/* service close */
void service_close(SERVICE *service)
{
    if(service)
    {
        service_stop(service);
        service->sbase->remove_service(service->sbase, service);
        service_clean(service);
    }
    return ;
}

/* Initialize service */
SERVICE *service_init()
{
    SERVICE *service = NULL;
    if((service = (SERVICE *)xmm_mnew(sizeof(SERVICE))))
    {
        MUTEX_INIT(service->mutex);
        service->etimer             = EVTIMER_INIT();
        service->set                = service_set;
        service->run                = service_run;
        service->set_log            = service_set_log;
        service->set_log_level      = service_set_log_level;
        service->stop               = service_stop;
        service->newproxy           = service_newproxy;
        service->newconn            = service_newconn;
        service->okconn             = service_okconn;
        service->addconn            = service_addconn;
        service->pushconn           = service_pushconn;
        service->popconn            = service_popconn;
        service->getconn            = service_getconn;
        service->freeconn           = service_freeconn;
        service->findconn           = service_findconn;
        service->overconn           = service_overconn;
        service->set_session        = service_set_session;
        service->add_multicast      = service_add_multicast;
        service->new_multicast      = service_new_multicast;
        service->drop_multicast     = service_drop_multicast;
        service->broadcast          = service_broadcast;
        service->addgroup           = service_addgroup;
        service->closegroup         = service_closegroup;
        service->castgroup          = service_castgroup;
        service->stategroup         = service_stategroup;
        service->newtask            = service_newtask;
        service->newtransaction     = service_newtransaction;
        service->set_heartbeat      = service_set_heartbeat;
        service->clean              = service_clean;
        service->close              = service_close;
    }
    return service;
}
