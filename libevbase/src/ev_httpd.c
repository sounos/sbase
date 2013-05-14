#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "evbase.h"
#ifdef HAVE_EVKQUEUE
#define CONN_MAX 1024
#else
#define CONN_MAX 4096
#endif
#define EV_BUF_SIZE 1024
#define CONN_BACKLOG_MAX 8192
static int connections = 0;
static int lfd = 0;
static struct sockaddr_in sa = {0};	
static socklen_t sa_len = sizeof(struct sockaddr_in);
static EVBASE *evbase = NULL;
typedef struct _CONN
{
    int fd;
    int x;
    int nout;
    int n;
    int keepalive;
    EVENT event;
    char out[EV_BUF_SIZE];
    char buffer[EV_BUF_SIZE];
}CONN;
static CONN *conns = NULL;
static char *out_block = "<html><head><title>hello</title></head><body>hello</body></html>";
static char out_data[EV_BUF_SIZE];
static int out_data_len = 0;
static char kout_data[EV_BUF_SIZE];
static int kout_data_len = 0;
void ev_handler(int fd, int ev_flags, void *arg)
{
    int rfd = 0, n = 0, out_len = 0;
    struct 	sockaddr_in rsa;
    socklen_t rsa_len = sizeof(struct sockaddr_in);
    char *out = NULL;

    if(fd == lfd )
    {
        if((ev_flags & E_READ))
        {
            while((rfd = accept(fd, (struct sockaddr *)&rsa, &rsa_len)) > 0)
            {
                fprintf(stderr, "Accept new connection %s:%d via %d total %d\r\n",
                        inet_ntoa(rsa.sin_addr), ntohs(rsa.sin_port),
                        rfd, ++connections);
                conns[rfd].fd = rfd;
                /* set FD NON-BLOCK */
                conns[rfd].n = 0;
                fcntl(rfd, F_SETFL, fcntl(rfd, F_GETFL, 0)|O_NONBLOCK);
                event_set(&(conns[rfd].event), rfd, E_READ|E_PERSIST,
                            (void *)&(conns[rfd].event), &ev_handler);
                evbase->add(evbase, &(conns[rfd].event));
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
                    event_add(&conns[fd].event, E_WRITE);	
                }
            }		
            else
            {
                if(n < 0 )
                    fprintf(stderr, "Reading data from %d failed, %s\r\n", fd, strerror(errno));
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
                if(n < 0)
                    fprintf(stderr, "writting data to %d failed, %s\r\n", fd, strerror(errno));	
                goto err;
            }
            event_del(&conns[fd].event, E_WRITE);
        }
        return ;
err:
        {
            event_destroy(&(conns[fd].event));
            memset(&(conns[fd]), 0, sizeof(CONN));
            shutdown(fd, SHUT_RDWR);
            close(fd);
            fprintf(stderr, "Connection %d closed\r\n", fd);
        }
        return ;
    }
}

int main(int argc, char **argv)
{
    int port = 0, fd = 0, opt = 1, i = 0;

    if(argc < 2)
    {
        fprintf(stderr, "Usage:%s port\r\n", argv[0]);	
        _exit(-1);
    }	
    port = atoi(argv[1]);
    /* Initialize global vars */
    if((conns = (CONN *)calloc(CONN_MAX, sizeof(CONN))))
    {
        memset(&sa, 0, sizeof(struct sockaddr_in));	
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = INADDR_ANY;
        sa.sin_port = htons(port);
        sa_len = sizeof(struct sockaddr_in);
        /* Initialize inet */ 
        lfd = socket(AF_INET, SOCK_STREAM, 0);
        if(setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR,(char *)&opt, (socklen_t) sizeof(opt)) != 0
#ifdef SO_REUSEPORT
         || setsockopt(lfd, SOL_SOCKET, SO_REUSEPORT, (char *)&opt, (socklen_t) sizeof(opt)) != 0
#endif
          )
        {
            fprintf(stderr, "set[SO_REUSEADDR] on fd[%d] failed, %s\r\n", fd, strerror(errno));
            _exit(-1);
        }
        /* Bind */
        if(bind(lfd, (struct sockaddr *)&sa, sa_len) != 0 )
        {
            fprintf(stderr, "Binding failed, %s\r\n", strerror(errno));
            return -1;
        }
        /* set FD NON-BLOCK */
        if(fcntl(lfd, F_SETFL, fcntl(lfd, F_GETFL, 0)|O_NONBLOCK) != 0 )
        {
            fprintf(stderr,"Setting NON-BLOCK failed, %s\r\n", strerror(errno));
            return -1;
        }
        /* Listen */
        if(listen(lfd, CONN_BACKLOG_MAX) != 0 )
        {
            fprintf(stderr, "Listening port:%d  failed, %s", port,strerror(errno));
            return -1;
        }
        out_data_len = sprintf(out_data, "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n"
                "Content-Length: %d\r\n\r\n%s", (int)strlen(out_block), out_block);
        kout_data_len = sprintf(kout_data, "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n"
                "Connection: Keep-Alive\r\nContent-Length: %d\r\n\r\n%s", 
                (int)strlen(out_block), out_block);

        /* set evbase */
        if((evbase = evbase_init(0)))
        {
            //evbase->set_evops(evbase, EOP_POLL);
            event_set(&conns[lfd].event, lfd, E_READ|E_EPOLL_ET|E_PERSIST, 
                    (void *)&conns[lfd].event, &ev_handler);
            evbase->add(evbase, &conns[lfd].event);
            do
            {
                evbase->loop(evbase, 0, NULL);
            }while(1);
        }
        for(i = 0; i < CONN_MAX; i++)
        {
            event_destroy(&conns[i].event);
            shutdown(conns[i].fd, SHUT_RDWR);
            close(conns[i].fd);
        }
        free(conns);
    }
    return 0;
}
