#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#ifdef USE_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#endif
#include "evbase.h"
#include "log.h"
#include "timer.h"
#ifdef HAVE_EVKQUEUE
#define CONN_MAX 10240
#else
#define CONN_MAX 40960
#endif
#define EV_BUF_SIZE 8192
static int running_status = 0;
static EVBASE *evbase = NULL;
static int ev_sock_type = 0;
static int ev_sock_list[] = {SOCK_STREAM, SOCK_DGRAM, SOCK_RDM};
static int ev_sock_count  = 2;
static int is_use_ssl = 0;
static int ncompleted = 0;
static int nrequest = 0;
static struct sockaddr_in xsa;
static socklen_t xsa_len = sizeof(struct sockaddr);
static int sock_type = 0;
static char *ip = NULL;
static int port = 0;
static int conn_num = 0;
static int limit = 0;
static int keepalive = 0;
void *timer = NULL;
void ev_handler(int fd, int ev_flags, void *arg);
void ev_udp_handler(int fd, int ev_flags, void *arg);
#ifdef USE_SSL
static SSL_CTX *ctx = NULL;
#endif
typedef struct _CONN
{
    int fd;
    int nreq;
    int nresp;
    char request[EV_BUF_SIZE];
    char response[EV_BUF_SIZE];
    EVENT event;
#ifdef USE_SSL
    SSL *ssl;
#endif
}CONN;
static CONN *conns = NULL;

int setrlimiter(char *name, int rlimit, int nset)
{
    int ret = -1;
    struct rlimit rlim;
    if(name)
    {
        if(getrlimit(rlimit, &rlim) == -1)
            return -1;
        if(rlim.rlim_cur > nset && rlim.rlim_max > nset)
            return 0;
        rlim.rlim_cur = nset;
        rlim.rlim_max = nset;
        if((ret = setrlimit(rlimit, &rlim)) == 0)
        {
            fprintf(stdout, "setrlimit %s cur[%ld] max[%ld]\n",
                    name, (long)rlim.rlim_cur, (long)rlim.rlim_max);
            return 0;
        }
        else
        {
            fprintf(stderr, "setrlimit %s cur[%ld] max[%ld] failed, %s\n",
                    name, (long)rlim.rlim_cur, (long)rlim.rlim_max, strerror(errno));
        }
    }
    return ret;
}

int new_request()
{
    int fd = 0, flag = 0, n = 0, opt = 1, prot = 0;
    struct sockaddr_in  lsa;
    socklen_t lsa_len = sizeof(struct sockaddr);

    if(ncompleted > 0 && ncompleted%1000 == 0)
    {
        TIMER_SAMPLE(timer);
        fprintf(stdout, "request:%d completed:%d time:%lld avg:%lld\n", nrequest, ncompleted, PT_USEC_U(timer), (long long int)ncompleted * 1000000ll/PT_USEC_U(timer));
    }
    if(sock_type == SOCK_DGRAM) prot = IPPROTO_UDP;
    if(nrequest < limit && (fd = socket(AF_INET, sock_type, prot)) > 0)
    {
        conns[fd].fd = fd;
        if(is_use_ssl && sock_type == SOCK_STREAM)
        {
            /* Connect */
            if(connect(fd, (struct sockaddr *)&xsa, xsa_len) != 0)
            {
                FATAL_LOG("Connect to %s:%d failed, %s", ip, port, strerror(errno));
                _exit(-1);
            }
#ifdef USE_SSL
            conns[fd].ssl = SSL_new(ctx);
            if(conns[fd].ssl == NULL )
            {
                FATAL_LOG("new SSL with created CTX failed:%s\n",
                        ERR_reason_error_string(ERR_get_error()));
                _exit(-1);
            }
            if(SSL_set_fd(conns[fd].ssl, fd) == 0)
            {
                FATAL_LOG("add SSL to tcp socket failed:%s\n",
                        ERR_reason_error_string(ERR_get_error()));
                _exit(-1);
            }
            /* SSL Connect */
            if(SSL_connect(conns[fd].ssl) < 0)
            {
                FATAL_LOG("SSL connection failed:%s\n",
                        ERR_reason_error_string(ERR_get_error()));
                _exit(-1);
            }
#endif
        }
        /* set FD NON-BLOCK */
        if(sock_type == SOCK_STREAM)
        {
           flag = fcntl(fd, F_GETFL, 0)|O_NONBLOCK;
            fcntl(fd, F_SETFL, flag);
            event_set(&conns[fd].event, fd, E_READ|E_WRITE|E_PERSIST, 
                    (void *)&(conns[fd].event), &ev_handler);
        }
        else
        {
            memset(&lsa, 0, sizeof(struct sockaddr));
            lsa.sin_family = AF_INET;
            if(setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, 
                        (char *)&opt, (socklen_t) sizeof(int)) != 0
#ifdef SO_REUSEPORT
                    || setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, 
                        (char *)&opt, (socklen_t) sizeof(int)) != 0
#endif
                    || bind(fd, (struct sockaddr *)&lsa, sizeof(struct sockaddr)) != 0) 
            {
                FATAL_LOG("Bind %d to %s:%d failed, %s",
                        fd, inet_ntoa(lsa.sin_addr), ntohs(lsa.sin_port), strerror(errno));
                close(fd);
                return -1;
            }
            //while(1)sleep(1);
            /* Connect */
            /*
            if(connect(fd, (struct sockaddr *)&xsa, xsa_len) != 0)
            {
                FATAL_LOG("Connect to %s:%d failed, %s", ip, port, strerror(errno));
                _exit(-1);
            }
            */
            getsockname(fd, (struct sockaddr *)&lsa, &lsa_len);
            SHOW_LOG("Connected to remote[%s:%d] local[%s:%d] via %d", ip, port, inet_ntoa(lsa.sin_addr), ntohs(lsa.sin_port), fd);
            n = atoi(ip);
            if(n >= 224 && n <= 239)
            {
                struct ip_mreq mreq;
                memset(&mreq, 0, sizeof(struct ip_mreq));
                mreq.imr_multiaddr.s_addr = inet_addr(ip);
                mreq.imr_interface.s_addr = INADDR_ANY;
                if(setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP,(char*)&mreq, sizeof(mreq)) != 0)
                {
                    SHOW_LOG("Setsockopt(MULTICAST) failed, %s", strerror(errno));
                    return -1;
                }
                if(setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &lsa.sin_addr, sizeof(struct in_addr)) < 0)
                {
                    FATAL_LOG("Setsockopt(IP_MULTICAST_IF) failed, %s", strerror(errno));
                    return -1;
                }
            }
            event_set(&conns[fd].event, fd, E_READ|E_WRITE|E_PERSIST, 
                    (void *)&(conns[fd].event), &ev_udp_handler);
        }
        evbase->add(evbase, &(conns[fd].event));
        conns[fd].nresp = 0;
        if(keepalive)
            conns[fd].nreq = sprintf(conns[fd].request, "GET / HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n");
        else
            conns[fd].nreq = sprintf(conns[fd].request, "GET / HTTP/1.0\r\n\r\n");
    }
    else
    {
        if(ncompleted >= limit) running_status = 0;
    }
    return 0;
}

/* sock_dgram /UCP handler */
void ev_udp_handler(int fd, int ev_flags, void *arg)
{
    int n = 0;
    struct sockaddr_in rsa;
    socklen_t rsa_len = sizeof(struct sockaddr);
    if(ev_flags & E_READ)
    {
        if((n = recvfrom(fd, conns[fd].response, EV_BUF_SIZE - 1, 
                        0, (struct sockaddr *)&rsa, &rsa_len)) > 0 )
        {
            SHOW_LOG("Read %d bytes from %d", n, fd);
            conns[fd].response[n] = 0;
            SHOW_LOG("Updating event[%p] on %d ", &conns[fd].event, fd);
            event_add(&conns[fd].event, E_WRITE);	
        }		
        else
        {
            if(n < 0 )
                FATAL_LOG("Reading from %d failed, %s", fd, strerror(errno));
            goto err;
        }
    }
    if(ev_flags & E_WRITE)
    {
        if((n = sendto(fd, conns[fd].request, conns[fd].nreq, 0, &xsa, sizeof(struct sockaddr))) == conns[fd].nreq)
        {
            SHOW_LOG("Wrote %d bytes via %d", n, fd);
        }
        else
        {
            if(n < 0)
                FATAL_LOG("Wrote data via %d failed, %s", fd, strerror(errno));	
            goto err;
        }
        event_del(&conns[fd].event, E_WRITE);
    }
    return ;
err:
    {
        event_destroy(&conns[fd].event);
        shutdown(fd, SHUT_RDWR);
        close(fd);
        SHOW_LOG("Connection %d closed", fd);
    }
}

/* sock stream/TCP handler */
void ev_handler(int fd, int ev_flags, void *arg)
{
    char *p = NULL, *s = NULL, *ks = "Content-Length:";
    int n = 0, x = 0;

    if(ev_flags & E_READ)
    {
        if(is_use_ssl)
        {
#ifdef USE_SSL
            n = SSL_read(conns[fd].ssl, conns[fd].response+conns[fd].nresp, EV_BUF_SIZE - conns[fd].nresp);
#else
            n = read(fd, conns[fd].response+conns[fd].nresp, EV_BUF_SIZE - conns[fd].nresp);
#endif
        }
        else
        {
            n = read(fd, conns[fd].response+conns[fd].nresp, EV_BUF_SIZE - conns[fd].nresp);
        }
        if(n > 0 )
        {
            SHOW_LOG("Read %d bytes from %d", n, fd);
            conns[fd].response[conns[fd].nresp] = 0;
            conns[fd].nresp += n;
            if(keepalive && (s = strstr(conns[fd].response, "\r\n\r\n")))
            {
                fprintf(stdout, "%s::%d n:%d x:%d\n", __FILE__, __LINE__, n, x);
                s += 4;
                x = conns[fd].nresp - (s  - conns[fd].response);
                if((p = strcasestr(conns[fd].response, ks)))
                {
                    p += strlen(ks);
                    while(*p != 0 && *p == 0x20)++p;
                    n = atoi(p);
                }
                if(x == n)
                    event_add(&(conns[fd].event), E_WRITE);
            }
        }	
        else
        {
            if(n < 0 )
                FATAL_LOG("Reading from %d failed, %s", fd, strerror(errno));
            goto err;
        }
    }
    if(ev_flags & E_WRITE)
    {
        if(is_use_ssl)
        {
#ifdef USE_SSL
            n = SSL_write(conns[fd].ssl, conns[fd].request, conns[fd].nreq);
#else
            n = write(fd, conns[fd].request, conns[fd].nreq);
#endif
        }
        else
        {
            n = write(fd, conns[fd].request, conns[fd].nreq);
        }
        if(n == conns[fd].nreq )
        {
            conns[fd].nresp = 0;
            nrequest++;
            SHOW_LOG("Wrote %d bytes via %d", n, fd);
        }
        else
        {
            if(n < 0)
                FATAL_LOG("Wrote data via %d failed, %s", fd, strerror(errno));	
            goto err;
        }
        event_del(&conns[fd].event, E_WRITE);
    }
    return ;
err:
    {
        event_destroy(&(conns[fd].event));
#ifdef USE_SSL
        if(conns[fd].ssl)
        {
            SSL_shutdown(conns[fd].ssl);
            SSL_free(conns[fd].ssl);
            conns[fd].ssl = NULL;
        }
#endif
        memset(&(conns[fd].event), 0, sizeof(EVENT));
        conns[fd].nresp = 0;
        shutdown(fd, SHUT_RDWR);
        conns[fd].fd = 0;
        close(fd);
       //SHOW_LOG("Connection %d closed", fd);
        ncompleted++; 
        new_request();
    }
}

int main(int argc, char **argv)
{
    int i = 0;

    if(argc < 7)
    {
        fprintf(stderr, "Usage:%s sock_type(0/TCP|1/UDP) iskeepalive ip port concurrecy limit\n", argv[0]);	
        _exit(-1);
    }	
    ev_sock_type = atoi(argv[1]);
    if(ev_sock_type < 0 || ev_sock_type > ev_sock_count)
    {
        fprintf(stderr, "sock_type must be 0/TCP OR 1/UDP\n");
        _exit(-1);
    }
    sock_type = ev_sock_list[ev_sock_type];
    keepalive = atoi(argv[2]);
    ip = argv[3];
    port = atoi(argv[4]);
    conn_num = atoi(argv[5]);
    limit = atoi(argv[6]);
    TIMER_INIT(timer);
    /* Set resource limit */
    setrlimiter("RLIMIT_NOFILE", RLIMIT_NOFILE, CONN_MAX);	
    /* Initialize global vars */
    if((conns = (CONN *)calloc(CONN_MAX, sizeof(CONN))))
    {
        //memset(events, 0, sizeof(EVENT *) * CONN_MAX);
        /* Initialize inet */ 
        memset(&xsa, 0, sizeof(struct sockaddr_in));	
        xsa.sin_family = AF_INET;
        xsa.sin_addr.s_addr = inet_addr(ip);
        xsa.sin_port = htons(port);
        xsa_len = sizeof(struct sockaddr);
        /* set evbase */
        if((evbase = evbase_init(0)))
        {
            if(is_use_ssl)
            {
#ifdef USE_SSL
                SSL_library_init();
                OpenSSL_add_all_algorithms();
                SSL_load_error_strings();
                if((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL)
                {
                    ERR_print_errors_fp(stdout);
                    _exit(-1);
                }
#endif
            }
            for(i = 0; i < conn_num; i++)
            {
                new_request();
                i++;
            }
            running_status = 1;
            do
            {
                evbase->loop(evbase, 0, NULL);
                //usleep(1000);
            }while(running_status);
            for(i = 0; i < CONN_MAX; i++)
            {
                if(conns[i].fd > 0)
                {
                    event_destroy(&conns[i].event);
                    shutdown(conns[i].fd, SHUT_RDWR);
                    close(conns[i].fd);
#ifdef USE_SSL
                    if(conns[i].ssl)
                    {
                        SSL_shutdown(conns[i].ssl);
                        SSL_free(conns[i].ssl); 
                    }
#endif
                }
            }
#ifdef USE_SSL
            ERR_free_strings();
            SSL_CTX_free(ctx);
#endif
        }
        free(conns);
        TIMER_CLEAN(timer);
    }
    return -1;
}
