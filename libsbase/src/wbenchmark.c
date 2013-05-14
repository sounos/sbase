#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <locale.h>
#include <netdb.h>
#include <sbase.h>
#include "timer.h"
#include "logger.h"
#include "mutex.h"
#include <sys/resource.h>
#define HTTP_BUF_SIZE       65536
#define HTTP_PATH_MAX       8192
#define HTTP_IP_MAX         16
#define HTTP_WAIT_TIMEOUT   200
static SBASE *sbase = NULL;
static SERVICE *service = NULL;
static int concurrency = 1;
static int ncurrent = 0;
static int ntasks = 1024;
static int nrequests = 0;
static int ntimeouts = 0;
static int nerrors = 0;
static int ncompleted = 0;
static int is_quiet = 0;
static int is_daemon = 0;
static int is_keepalive = 0;
static int workers = 8;
static int is_post = 0;
static int is_verbosity = 0;
static char *server_host = NULL;
static char server_ip[HTTP_IP_MAX];
static int server_port = 80;
static char *server_url = "";
static char *server_argv = "";
static int server_is_ssl = 0;
static char request[HTTP_BUF_SIZE];
static int request_len = 0; 
static void *timer = NULL;
static int running_status = 0;
static int req_timeout = 1000000;
static FILE *fp = NULL;
static void *logger = NULL;
static MUTEX *mutex;

CONN *http_newconn(int id, char *ip, int port, int is_ssl)
{
    CONN *conn = NULL;

    if(running_status && ip && port > 0)
    {
        if(is_ssl) service->session.flags |= SB_USE_SSL;
        if((conn = service->newconn(service, -1, -1, ip, port, NULL)))
        {
            conn->c_id = id;
        }
        else
        {
            FATAL_LOGGER(logger, "new_conn(%s:%d) falied, %s", ip, port, strerror(errno));
        }
    }
    return conn;
}



/* http request */
int http_request(CONN *conn)
{
    char *p = NULL, path[HTTP_PATH_MAX], buf[HTTP_BUF_SIZE];
    int n = 0;

    if(running_status && conn)
    {
        //fprintf(stdout, "%s::%d conn[%d]->status:%d\n", __FILE__, __LINE__, conn->fd, conn->status);
        MUTEX_LOCK(mutex);
        if(nrequests < ntasks)
        {
            n = nrequests++;
        }
        else
        {
            n = nrequests;
        }
        MUTEX_UNLOCK(mutex);
        if(n >= ntasks)
        {
            //WARN_LOGGER(logger, "close-conn[%s:%d] via %d", conn->local_ip, conn->local_port, conn->fd);
            conn->close(conn);
            return -1;
        }
        conn->set_timeout(conn, req_timeout);
        if(fp && fgets(path, HTTP_PATH_MAX, fp))
        {
            //fprintf(stdout, "%s::%d conn[%s:%d][%d]->status:%d\n", __FILE__, __LINE__, conn->local_ip, conn->local_port, conn->fd, conn->status);
            p = path;
            while(*p != '\0' && *p != '\n' && *p != '\r')++p;
            *p = '\0';
            if(is_post)
            {
                p = buf;
                p += sprintf(p, "POST /%s HTTP/1.1\r\n", path);
                p += sprintf(p, "Host: %s:%d\r\n", server_host, server_port);
                if(is_keepalive) p += sprintf(p, "Connection: Keep-Alive\r\n");
                p += sprintf(p, "Content-Length: %d\r\n\r\n", (int)strlen(server_argv));
                p += sprintf(p, "\r\n");
                if(strlen(server_argv) > 0) p += sprintf(p, "%s", server_argv);
                n = p - buf;
            }
            else
            {
                p = buf;
                if(strlen(server_argv) > 0) 
                    p += sprintf(p, "GET /%s?%s HTTP/1.1\r\n", path, server_argv);
                else 
                    p += sprintf(p, "GET /%s HTTP/1.1\r\n", path);
                p += sprintf(p, "Host: %s:%d\r\n", server_host, server_port);
                if(is_keepalive) p += sprintf(p, "Connection: Keep-Alive\r\n");
                p += sprintf(p, "\r\n");
                n = p - buf;
            }
            if(is_verbosity && is_quiet == 0) fprintf(stdout, "%s", buf);
            conn->save_cache(conn, path, strlen(path)+1);
            return conn->push_chunk(conn, buf, n);
        }
        else
        {
            return conn->push_chunk(conn, request, request_len);
        }
    }
    return -1;
}

int http_show_state(int n)
{
    int nok = 0;
    TIMER_SAMPLE(timer);
    nok = n - ntimeouts;
    if(PT_USEC_U(timer) > 0 && nok  > 0)
    {
        if(is_quiet)
        {
            REALLOG(logger, "timeout:%d error:%d ok:%d total:%d "
                    "time used:%lld request per sec:%lld avg_time:%lld", 
                    ntimeouts, nerrors, nok, n, PT_USEC_U(timer), 
                    (((long long int)nok * 1000000ll)/PT_USEC_U(timer)),
                    (PT_USEC_U(timer)/nok));
        }
        else
        {
            fprintf(stdout, "timeout:%d error:%d ok:%d total:%d\n"
                    "time used:%lld request per sec:%lld avg_time:%lld\n", 
                    ntimeouts, nerrors, nok, n, PT_USEC_U(timer), 
                    ((long long int)nok * 1000000ll/PT_USEC_U(timer)),
                    (PT_USEC_U(timer)/nok));
        }
    }
    running_status = 0;sbase->stop(sbase);
    return 0;
}
/* new request */
int http_new_request(int id)
{
    if(http_newconn(id, server_ip, server_port, server_is_ssl)  == NULL)
    {
        if(ncurrent > 0)--ncurrent;
    }
    return 0;
}

/* http over */
int http_over(CONN *conn, int respcode)
{
    int id = 0, n = 0, m = 0, nerror = 0, ntimeout = 0;

    if(conn)
    {
        MUTEX_LOCK(mutex);
        if(ncompleted < ntasks)
        {
            n = ++ncompleted; 
            m = nrequests;
            nerror = nerrors; 
            ntimeout = ntimeouts;
        }
        MUTEX_UNLOCK(mutex);
        //WARN_LOGGER(logger, "complete %d conn[%s:%d] via %d", n, conn->local_ip, conn->local_port, conn->fd);
        id = conn->c_id;
        if(n > 0 && n <= ntasks && (n%1000) == 0)
        {
            if(is_quiet)
            {
                REALLOG(logger, "requests:%d completed:%d error:%d timeout:%d concurrecy:%d", m, n, nerror, ntimeout, ncurrent);
            }
            else 
            {
                fprintf(stdout, "requests:%d completed:%d error:%d timeout:%d concurrecy:%d\n", m, n, nerror, ntimeout, ncurrent);
            }
        }
        if(m < ntasks)
        {
            if(conn->d_state  == 0 && is_keepalive && respcode == 200) 
            {
                return http_request(conn);
            }
            else
            {
                if(is_keepalive) conn->close(conn);
                //if(respcode != 0 && respcode != 200)nerrors++;
                if(http_newconn(id, server_ip, server_port, server_is_ssl)  == NULL) 
                {
                    if(ncurrent > 0)--ncurrent;
                }
            }
        }
        else 
        {
            --ncurrent;
            conn->close(conn);
        }
        if(running_status && n == ntasks)
        {
            return http_show_state(n);
        }
    }
    return -1;
}

int http_check_over(CONN *conn)
{
    if(conn)
    {
        conn->over_timeout(conn);
        if(is_keepalive) return http_over(conn, conn->s_id);
        return 0;
    }
    return -1;
}

int benchmark_packet_reader(CONN *conn, CB_DATA *buffer)
{
    return 0;
}

int benchmark_packet_handler(CONN *conn, CB_DATA *packet)
{
    char *p = NULL, *end = NULL, *s = NULL;
    int respcode = -1;
    long long int len = 0;

	if(conn)
    {
        conn->over_timeout(conn);
        p = packet->data;end = packet->data + packet->ndata;
        //check response code 
        if((s = strstr(p, "HTTP/")))
        {
            s += 5;
            while(*s != 0x20 && s < end)++s;
            while(*s == 0x20)++s;
            if(*s >= '0' && *s <= '9') respcode = atoi(s);
        }
        conn->s_id = respcode;
        if(respcode != 200 && respcode != 204) nerrors++;
        /*
        if(respcode != 200)
        {
            //fprintf(stdout, "HTTP:%s\n", p);
            conn->over_timeout(conn);
            return http_over(conn, respcode);
        }
        */
        //check Content-Length
        if((s = strcasestr(p, "Content-Length")))
        {
            s += 14;
            while(s < end)
            {
                if(*s >= '0' && *s <= '9')break;
                else ++s;
            }
            if(*s >= '0' && *s <= '9' && (len = atoll(s)) > 0) 
            {
                conn->recv_chunk(conn, len);
            }
            else
            {
                return http_check_over(conn);
            }
        }
        else
        {
                return http_check_over(conn);
        }
    }
    return -1;
}

int benchmark_data_handler(CONN *conn, CB_DATA *packet, CB_DATA *cache, CB_DATA *chunk)
{
    if(conn)
    {
        return http_check_over(conn);
    }
    return 0;
}

/* transaction handler */
int benchmark_trans_handler(CONN *conn, int tid)
{
    if(conn)
    {
    }
    return 0;
}

/* error handler */
int benchmark_error_handler(CONN *conn, CB_DATA *packet, CB_DATA *cache, CB_DATA *chunk)
{
    if(conn)
    {
        //fprintf(stdout, "%s::%d s_id:%d current:%d\n", __FILE__, __LINE__, conn->s_id, ncurrent);
        return http_over(conn, conn->s_id);
    }
    return -1;
}

/* ok handler */
int benchmark_ok_handler(CONN *conn)
{
    if(conn)
    {
        //WARN_LOGGER(logger, "ok_handler conn[%s:%d] via %d", conn->local_ip, conn->local_port, conn->fd);
        return http_request(conn);
    }
    return -1;
}

/* timeout handler*/
int benchmark_timeout_handler(CONN *conn, CB_DATA *packet, CB_DATA *cache, CB_DATA *chunk)
{
    if(conn)
    {
        if(cache && cache->data)
        {
            WARN_LOGGER(logger, "timeout on conn[%s:%d] uri[%s] via %d status:%d", conn->local_ip, conn->local_port, cache->data, conn->fd, conn->status);
        }
        else
        {
            WARN_LOGGER(logger, "timeout on conn[%s:%d] via %d status:%d", conn->local_ip, conn->local_port, conn->fd, conn->status);
        }
        ntimeouts++;
        conn->over_estate(conn);
        conn->over_timeout(conn);
        http_over(conn, 0);
        return conn->close(conn);
    }
    return -1;
}

int benchmark_oob_handler(CONN *conn, CB_DATA *oob)
{
    if(conn)
    {
        return 0;
    }
    return -1;
}

/* heartbeat */
void benchmark_heartbeat_handler(void *arg)
{
    CONN *conn = NULL;
    int id = 0;
    if(running_status == 0)
    {
        running_status = 1;
        while(ncurrent < concurrency)
        {
            id = ncurrent;
            if((conn = http_newconn(id, server_ip, server_port, server_is_ssl)) == NULL)
            {
                break;
            }
            else
            {
                usleep(10);
                ++ncurrent;
            }
        }
    }
    return ;
}

static void benchmark_stop(int sig)
{
    switch (sig) 
    {
        case SIGINT:
        case SIGTERM:
            fprintf(stderr, "benchmark  is interrupted by user.\n");
            running_status = 0;
            http_show_state(ncompleted);
            if(sbase)sbase->stop(sbase);
            break;
        default:
            break;
    }
}

int main(int argc, char **argv)
{
    pid_t pid;
    char *url = NULL, *urllist = NULL, line[HTTP_BUF_SIZE], *s = NULL, *p = NULL, ch = 0;
    struct hostent *hent = NULL;
    int n = 0, log_level = 0, tcp_option = 0, socket_option = 0, niodaemons = 0, is_realtime = 0;

    /* get configure file */
    while((ch = getopt(argc, argv, "vqpkdr:i:s:x:w:l:c:t:n:e:")) != -1)
    {
        switch(ch)
        {
            case 'c': 
                concurrency = atoi(optarg);
                break;
            case 'n':
                ntasks = atoi(optarg);
                break;
            case 'l':
                urllist = optarg;
                break;
            case 'k':
                is_keepalive = 1;
                break;
            case 'w':
                if((n = atoi(optarg)) > 0) workers = n;
                break;
            case 'd':
                is_daemon = 1;
                break;
            case 'q':
                is_quiet = 1;
                break;
            case 'r':
                is_realtime = atoi(optarg);
                break;
            case 't':
                req_timeout = atoi(optarg);
                break;
            case 'p':
                is_post = 1;
                break;
            case 'x':
                tcp_option = atoi(optarg);
                break;
            case 's':
                socket_option = atoi(optarg);
                break;
            case 'i':
                niodaemons = atoi(optarg);
                break;
            case 'e':
                log_level = atoi(optarg);
                break;
            case 'v':
                is_verbosity = 1;
                break;
            case '?':
                url = argv[optind];
                break;
            default:
                break;
        }
    }
    if(url == NULL && optind < argc)
    {
        //fprintf(stdout, "opt:%c optind:%d arg:%s\n", ch, optind, argv[optind]);
        url = argv[optind];
    }
    //fprintf(stdout, "concurrency:%d nrequests:%d is_keepalive:%d is_daemon:%d\n",
    //       concurrency, ntasks, is_keepalive, is_daemon);
    if(url == NULL)
    {
        fprintf(stderr, "Usage:%s [options] http(s)://host:port/path\n"
                "Options:\n\t-c concurrency\n\t-n requests\n"
                "\t-w worker threads\n\t-e log level\n\t-x tcp_option 1:tcp_nodelay\n"
                "\t-s socket_option 1:socket_linger\n\t-i iodaemons\n"
                "\t-t timeout (microseconds, default 1000000)\n"
                "\t-r is_realtime_thread 1:SCHED_FIFO 2:SCHED_RR\n"
                "\t-p is_POST\n\t-v is_verbosity\n\t-l urllist file\n"
                "\t-k is_keepalive\n\t-d is_daemon\n ", argv[0]);
        _exit(-1);
    }
    p = url;
    s = line;
    while(*p != '\0')
    {
        if(*p >= 'A' && *p <= 'Z')
        {
            *s++ = *p++ + 'a' - 'A';
        }
        else if(*((unsigned char *)p) > 127 || *p == 0x20)
        {
            s += sprintf(s, "%%%02x", *((unsigned char *)p));
            ++p;
        }
        else *s++ = *p++;
    }
    *s = '\0';
    s = line;
    if(strncmp(s, "http://", 7) == 0)
    {
        s += 7;
        server_host = s;
    }
    else if(strncmp(s, "https://", 8) == 0)
    {
        s += 8;
        server_host = s;
        server_is_ssl = 1;
    }
    else goto invalid_url;
    while(*s != '\0' && *s != ':' && *s != '/')s++;
    if(*s == ':')
    {
        *s = '\0';
        ++s;
        server_port = atoi(s);          
        while(*s != '\0' && *s != '/')++s;
    }
    if(*s == '/')
    {
        *s = '\0';
        ++s;
        server_url = s;
    }
    while(*s != '\0' && *s != '?')++s;
    if(*s == '?')
    {
        *s = '\0';
        ++s;
        server_argv = s;
    }
invalid_url:
    if(server_host == NULL || server_port <= 0)
    {
        fprintf(stderr, "Invalid url:%s, url must be http://host:port/path?argv "
                " or https://host:port/path?argv\n", url);
        _exit(-1);
    }
    if(urllist) fp = fopen(urllist, "rd");
    if(is_post)
    {
        p = request;
        p += sprintf(p, "POST /%s HTTP/1.1\r\n", server_url);
        p += sprintf(p, "Host: %s:%d\r\n", server_host, server_port);
        if(is_keepalive) p += sprintf(p, "Connection: Keep-Alive\r\n");
        p += sprintf(p, "Content-Length: %d\r\n\r\n", (int)strlen(server_argv));
        p += sprintf(p, "\r\n");
        if(strlen(server_argv)) p += sprintf(p, "%s", server_argv);
        request_len = p - request;
    }
    else
    {
        p = request;
        if(strlen(server_argv) > 0)
            p += sprintf(p, "GET /%s?%s HTTP/1.1\r\n", server_url, server_argv);
        else 
            p += sprintf(p, "GET /%s HTTP/1.1\r\n", server_url);
        p += sprintf(p, "Host: %s:%d\r\n", server_host, server_port);
        if(is_keepalive) p += sprintf(p, "Connection: Keep-Alive\r\n");
        p += sprintf(p, "\r\n");
        request_len = p - request;
    }
    if((hent = gethostbyname(server_host)) == NULL)
    {
        fprintf(stderr, "resolve hostname:%s failed, %s\n", server_host, strerror(h_errno));
        _exit(-1);
    }
    else
    {
        //memcpy(&ip, &(hent->h_addr), sizeof(int));
        sprintf(server_ip, "%s", inet_ntoa(*((struct in_addr *)(hent->h_addr))));
        if(is_verbosity)
        {
            fprintf(stdout, "ip:%s request:%s\n", server_ip, request);
        }
    }
    //_exit(-1);
    /* locale */
    setlocale(LC_ALL, "C");
    /* signal */
    signal(SIGTERM, &benchmark_stop);
    signal(SIGINT,  &benchmark_stop);
    signal(SIGHUP,  &benchmark_stop);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);
    //daemon
    if(is_daemon)
    {
        pid = fork();
        switch (pid) {
            case -1:
                perror("fork()");
                exit(EXIT_FAILURE);
                break;
            case 0: //child
                if(setsid() == -1)
                    exit(EXIT_FAILURE);
                break;
            default://parent
                _exit(EXIT_SUCCESS);
                break;
        }
    }
    setrlimiter("RLIMIT_NOFILE", RLIMIT_NOFILE, 65536);
    if((sbase = sbase_init()) == NULL)
    {
        exit(EXIT_FAILURE);
        return -1;
    }
    sbase->nchilds = 0;
    sbase->usec_sleep = 1000;
    sbase->connections_limit = 65536;
    TIMER_INIT(timer);
    MUTEX_INIT(mutex);
    if(log_level > 1)sbase->set_evlog(sbase, "/tmp/benchmark_ev.log");
    if(log_level > 0) sbase->set_evlog_level(sbase, log_level);
    if((service = service_init()))
    {
        service->working_mode = 1;
        service->nprocthreads = workers;
        service->niodaemons = niodaemons;
        service->ndaemons = 0;
        service->use_cond_wait = 1;
        service->flag |= SB_USE_OUTDAEMON|SB_USE_COND;
        if(is_realtime) service->flag |= (SB_SCHED_FIFO|SB_SCHED_RR) & is_realtime;
        if(socket_option == 1) service->flag |= SB_SO_LINGER;
        if(tcp_option == 1) service->flag |= SB_TCP_NODELAY;
        service->service_type = C_SERVICE;
        service->family = AF_INET;
        service->sock_type = SOCK_STREAM;
        service->service_name = "benchmark";
        service->session.flags = SB_NONBLOCK;
        service->session.packet_type = PACKET_DELIMITER;
        service->session.packet_delimiter = "\r\n\r\n";
        service->session.packet_delimiter_length = 4;
        service->session.packet_handler = &benchmark_packet_handler;
        service->session.data_handler = &benchmark_data_handler;
        service->session.transaction_handler = &benchmark_trans_handler;
        service->session.error_handler = &benchmark_error_handler;
        service->session.timeout_handler = &benchmark_timeout_handler;
        service->session.ok_handler = &benchmark_ok_handler;
        service->session.buffer_size = 65536;
        service->set_heartbeat(service, 1000000, &benchmark_heartbeat_handler, NULL);
        //service->set_session(service, &session);
        service->set_log(service, "/tmp/benchmark.log");
        service->set_log_level(service, log_level);
        LOGGER_INIT(logger, "/tmp/benchmark_res.log");
        if(sbase->add_service(sbase, service) == 0)
        {
            sbase->running(sbase, 0);
            //sbase->running(sbase, 3600);
            //sbase->running(sbase, 90000000);sbase->stop(sbase);
        }
        else fprintf(stderr, "add service failed, %s", strerror(errno));
    }
    sbase->clean(sbase);
    MUTEX_DESTROY(mutex);
    return 0;
}
