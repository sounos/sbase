#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#define CONN_MAX 65536
#define EV_BUF_SIZE 1024
#define E_READ      0x01
#define E_WRITE     0x02
static int epollfd = 0;
static int max_connections = 0;
static int lfd = 0;
static struct sockaddr_in sa = {0};	
static socklen_t sa_len = sizeof(struct sockaddr_in);
static int ev_sock_type = 0;
static int ev_sock_list[] = {SOCK_STREAM, SOCK_DGRAM};
static int ev_sock_count = 2;
static in_addr_t multicast_addr = INADDR_NONE;
typedef struct _CONN
{
    int fd;
    int x;
    int nout;
    int n;
    int keepalive;
    char out[EV_BUF_SIZE];
    char buffer[EV_BUF_SIZE];
}CONN;
static CONN *conns = NULL;
static char *out_block = "daffffffffdsafhklsdfjlasfjl;adjfl;ajdsfl;ajdlf;jadl;fjl;sdmflsdmfl;asmfl;mdslfmadsl;fmad;lfmad;sffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm";
static char out_data[EV_BUF_SIZE];
static int out_data_len = 0;
static char kout_data[EV_BUF_SIZE];
static int kout_data_len = 0;
/* set rlimit */
int setrlimiter(char *name, int rlimit, int nset)
{
    int ret = -1;
    struct rlimit rlim;
    if(name)
    {
        if(getrlimit(rlimit, &rlim) == -1)
            return -1;
        else
        {
            fprintf(stdout, "getrlimit %s cur[%ld] max[%ld]\n", 
                    name, (long)rlim.rlim_cur, (long)rlim.rlim_max);
        }
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

void ev_handler(int fd, int ev_flags, void *arg)
{
    int rfd = 0, n = 0, out_len = 0;
    struct 	sockaddr_in rsa;
    socklen_t rsa_len = sizeof(struct sockaddr_in);
    struct epoll_event evp;
    char *out = NULL;

    if(fd == lfd )
    {
        if((ev_flags & E_READ))
        {
            while((rfd = accept(fd, (struct sockaddr *)&rsa, &rsa_len)) > 0)
            {
                conns[rfd].fd = rfd;
                /* set FD NON-BLOCK */
                conns[rfd].n = 0;
                fcntl(rfd, F_SETFL, fcntl(rfd, F_GETFL, 0)|O_NONBLOCK);
                memset(&evp, 0, sizeof(struct epoll_event));
                evp.data.fd = rfd;
                evp.events = EPOLLIN;
                epoll_ctl(epollfd, EPOLL_CTL_ADD, evp.data.fd, &evp);
            }
            return ;
        }
    }
    else
    {
        if(ev_flags & E_READ)
        {

            n = read(fd, conns[fd].buffer+conns[fd].n, EV_BUF_SIZE - conns[fd].n);
            if(n > 0)
            {
                conns[fd].n += n;
                conns[fd].buffer[conns[fd].n] = 0;
                if(strstr(conns[fd].buffer, "\r\n\r\n"))
                {
                    if(strcasestr(conns[fd].buffer, "Keep-Alive")) conns[fd].keepalive = 1;
                    conns[fd].x = 0;
                    conns[fd].n = 0;
                    memset(&evp, 0, sizeof(struct epoll_event));
                    evp.data.fd = fd;
                    evp.events = EPOLLOUT;
                    epoll_ctl(epollfd, EPOLL_CTL_MOD, evp.data.fd, &evp);
                }
            }		
            else
            {
                goto err;
            }
        }
        if(ev_flags & E_WRITE)
        {
            if(conns[fd].keepalive){out = kout_data;out_len = kout_data_len;}
            else {out = out_data; out_len = out_data_len;}
            n = write(fd, out + conns[fd].x, out_len - conns[fd].x);
            if(n > 0 )
            {
                conns[fd].x += n;
                if(conns[fd].x < out_len) return ;
                if(conns[fd].x  == out_len)
                {
                    conns[fd].x = 0;
                    conns[fd].n = 0;
                    if(conns[fd].keepalive == 0) goto err;
                    conns[fd].keepalive = 0;
                }
            }
            else
            {
                goto err;
            }
            memset(&evp, 0, sizeof(struct epoll_event));
            evp.data.fd = fd;
            evp.events = EPOLLIN;
            epoll_ctl(epollfd, EPOLL_CTL_MOD, evp.data.fd, &evp);
        }
        return ;
err:
        {
            memset(&evp, 0, sizeof(struct epoll_event));
            evp.data.fd = fd;
            epoll_ctl(epollfd, EPOLL_CTL_DEL, evp.data.fd, &evp);
            memset(&(conns[fd]), 0, sizeof(CONN));
            shutdown(fd, SHUT_RDWR);
            close(fd);
        }
        return ;
    }
}

int main(int argc, char **argv)
{
    int port = 0, connection_limit = 0, fd = 0, opt = 1, i = 0, nprocess = 0;
    char *multicast_ip = NULL;

    if(argc < 5)
    {
        fprintf(stderr, "Usage:%s sock_type(0/TCP|1/UDP) port "
                "connection_limit process_limit multicast_ip(only for UDP)\n", argv[0]);	
        _exit(-1);
    }	
    ev_sock_type = atoi(argv[1]);
    if(ev_sock_type < 0 || ev_sock_type > ev_sock_count)
    {
        fprintf(stderr, "sock_type must be 0/TCP OR 1/UDP\n");
        _exit(-1);
    }
    port = atoi(argv[2]);
    connection_limit = atoi(argv[3]);
    nprocess = atoi(argv[4]);
    if(argc > 5) multicast_ip = argv[5];
    max_connections = (connection_limit > 0) ? connection_limit : CONN_MAX;
    /* Set resource limit */
    setrlimiter("RLIMIT_NOFILE", RLIMIT_NOFILE, CONN_MAX);	
    out_data_len = sprintf(out_data, "HTTP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s", (int)strlen(out_block), out_block);
    kout_data_len = sprintf(kout_data, "HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\nContent-Length: %d\r\n\r\n%s", (int)strlen(out_block), out_block);


    /* Initialize global vars */
    if((conns = (CONN *)calloc(CONN_MAX, sizeof(CONN))))
    {
        memset(&sa, 0, sizeof(struct sockaddr_in));	
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = INADDR_ANY;
        sa.sin_port = htons(port);
        sa_len = sizeof(struct sockaddr_in );
        /* Initialize inet */ 
        lfd = socket(AF_INET, ev_sock_list[ev_sock_type], 0);
        if(setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR,
                    (char *)&opt, (socklen_t) sizeof(opt)) != 0
#ifdef SO_REUSEPORT
                || setsockopt(lfd, SOL_SOCKET, SO_REUSEPORT,
                    (char *)&opt, (socklen_t) sizeof(opt)) != 0
#endif
          )
        {
            fprintf(stderr, "setsockopt[SO_REUSEADDR] on fd[%d] failed, %s", fd, strerror(errno));
            _exit(-1);
        }
        /* Bind */
        if(bind(lfd, (struct sockaddr *)&sa, sa_len) != 0 )
        {
            //SHOW_LOG("Binding failed, %s", strerror(errno));
            return -1;
        }
        /* set FD NON-BLOCK */
        if(fcntl(lfd, F_SETFL, fcntl(lfd, F_GETFL, 0)|O_NONBLOCK) != 0 )
        {
            //SHOW_LOG("Setting NON-BLOCK failed, %s", strerror(errno));
            return -1;
        }
        /* Listen */
        if(ev_sock_list[ev_sock_type] == SOCK_STREAM)
        {
            if(listen(lfd, 10240) != 0 )
            {
                //SHOW_LOG("Listening  failed, %s", strerror(errno));
                return -1;
            }
        }
        /* set multicast */
        if(ev_sock_list[ev_sock_type] == SOCK_DGRAM && multicast_ip)
        {
            struct ip_mreq mreq;
            memset(&mreq, 0, sizeof(struct ip_mreq));
            mreq.imr_multiaddr.s_addr = multicast_addr = inet_addr(multicast_ip);
            mreq.imr_interface.s_addr = INADDR_ANY;
            if(setsockopt(lfd, IPPROTO_IP, IP_ADD_MEMBERSHIP,(char*)&mreq, sizeof(mreq)) != 0)
            {
                //SHOW_LOG("Setsockopt(MULTICAST) failed, %s", strerror(errno));
                return -1;
            }
        }
        //SHOW_LOG("Initialize evbase ");
        struct epoll_event evp, events[CONN_MAX];
        int flag = 0, n = 0;
        if((epollfd = epoll_create(CONN_MAX)) > 0)
        {
            memset(&evp, 0, sizeof(struct epoll_event));
            evp.data.fd = lfd;
            evp.events = EPOLLIN|EPOLLET;
            epoll_ctl(epollfd, EPOLL_CTL_ADD, lfd, &evp);
            do
            {
                n = epoll_wait(epollfd, events, CONN_MAX, -1);
                for(i = 0; i < n; i++)
                {
                    flag = 0;
                    if(events[i].events & (EPOLLERR|EPOLLHUP))
                        flag = E_READ|E_WRITE;
                    else 
                    {
                        if(events[i].events & EPOLLIN) flag |= E_READ;
                        if(events[i].events & EPOLLOUT) flag |= E_WRITE;
                    }
                    ev_handler(events[i].data.fd, flag, NULL);
                }
            }while(1);
            for(i = 0; i < CONN_MAX; i++)
            {
                shutdown(conns[i].fd, SHUT_RDWR);
                close(conns[i].fd);
            }
        }
        free(conns);
    }
    return 0;
}
//gcc -o sysepoll epoll.c && ./sysepoll 0 1980 65536 1
