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
static int ntimeout = 0;
static int nerrors = 0;
static int ncompleted = 0;
static int is_quiet = 0;
static int is_daemon = 0;
static int is_keepalive = 0;
static int workers = 32;
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

CONN *http_newconn(int id, char *ip, int port, int is_ssl)
{
    CONN *conn = NULL;

    if(running_status && ip && port > 0)
    {
        if(is_ssl) service->session.flags |= SB_USE_SSL;
        if((conn = service->newconn(service, -1, -1, ip, port, NULL)))
        {
            conn->c_id = id;
            conn->start_cstate(conn);
            //service->newtransaction(service, conn, id);
            //usleep(10);
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
        if(nrequests >= ntasks)
        {
            return -1;
        }
        if(nrequests == 0)
        {
            TIMER_INIT(timer);
        }
        ++nrequests;
        conn->start_cstate(conn);
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
                if(is_keepalive) p += sprintf(p, "Connection: KeepAlive\r\n");
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
                if(is_keepalive) p += sprintf(p, "Connection: KeepAlive\r\n");
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
    TIMER_SAMPLE(timer);
    if(PT_USEC_U(timer) > 0 && ncompleted > 0)
    {
        if(is_quiet)
        {
            REALLOG(logger, "timeout:%d error:%d total:%d "
                    "time used:%lld request per sec:%lld avg_time:%lld", 
                    ntimeout, nerrors, ncompleted, PT_USEC_U(timer), 
                    ((long long int)ncompleted * 1000000ll/PT_USEC_U(timer)),
                    (PT_USEC_U(timer)/ncompleted));
        }
        else
        {
            fprintf(stdout, "timeout:%d error:%d total:%d\n"
                    "time used:%lld request per sec:%lld avg_time:%lld\n", 
                    ntimeout, nerrors, ncompleted, PT_USEC_U(timer), 
                    ((long long int)ncompleted * 1000000ll/PT_USEC_U(timer)),
                    (PT_USEC_U(timer)/ncompleted));
        }
    }
    if(is_daemon == 0){running_status = 0;sbase->stop(sbase);}
    return 0;
}

/* http over */
int http_over(CONN *conn, int respcode)
{
    int id = 0, n = 0;

    if(conn)
    {
        conn->over_cstate(conn);
        id = conn->c_id;
        if(ncompleted < ntasks) 
            ++ncompleted;
        else 
            return conn->over(conn);
        n = ncompleted;
        if(n > 0 && n <= ntasks && (n%1000) == 0)
        {
            if(is_quiet)
            {
                REALLOG(logger, "completed %d current:%d", n, ncurrent);
            }
            else fprintf(stdout, "completed %d current:%d\n", n, ncurrent);
        }
        if(ncompleted < ntasks)
        {
            if(conn->d_state == 0 && is_keepalive && respcode != 0) 
                return http_request(conn);
            else
            {
                conn->close(conn);
                if(respcode != 0 && respcode != 200)nerrors++;
                if(http_newconn(id, server_ip, server_port, server_is_ssl)  == NULL) 
                {
                    if(ncurrent > 0)--ncurrent;
                }
            }
        }
        else 
        {
            conn->close(conn);
            if(n == ntasks) return http_show_state(n);
        }
    }
    return -1;
}

int http_check_over(CONN *conn)
{
    if(conn)
    {
        return http_over(conn, conn->s_id);
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
        p = packet->data;
        end = packet->data + packet->ndata;
        //check response code 
        if((s = strstr(p, "HTTP/")))
        {
            s += 5;
            while(*s != 0x20 && s < end)++s;
            while(*s == 0x20)++s;
            if(*s >= '0' && *s <= '9') respcode = atoi(s);
        }
        conn->s_id = respcode;
        //check Content-Length
        if((s = strstr(p, "Content-Length")) || (s = strstr(p, "content-length")))
        {
            s += 14;
            while(s < end)
            {
                if(*s >= '0' && *s <= '9')break;
                else++s;
            }
            if(*s >= '0' && *s <= '9' && (len = atoll(s)) > 0) 
                return conn->recv_chunk(conn, len);
        }
        return http_check_over(conn);
    }
    return -1;
}

int benchmark_data_handler(CONN *conn, CB_DATA *packet, CB_DATA *cache, CB_DATA *chunk)
{
    if(conn)
    {
        //fprintf(stdout, "%s::%d over on conn[%s:%d] c_state:%d s_state:%d via %d\n", __FILE__, __LINE__, conn->local_ip, conn->local_port, conn->c_state, conn->s_state, conn->fd);
        return http_check_over(conn);
    }
    return 0;
}

/* transaction handler */
int benchmark_trans_handler(CONN *conn, int tid)
{
    if(conn)
    {
        /*
        if(conn->status == 0)
        {
            //conn->over_evstate(conn);
            return http_request(conn);
        }
        else
        {
            if(conn->timeout >= req_timeout)
            {
                ACCESS_LOGGER(logger, "connecting timeout on conn[%s:%d] via %d status:%d", conn->local_ip, conn->local_port, conn->fd, conn->status);
                ntimeout++;
                return http_check_over(conn);
            }
            else
            {
                conn->wait_evstate(conn);
                return conn->set_timeout(conn, req_timeout - conn->timeout);
            }
            //return service->newtransaction(service, conn, tid);
        }
        */
    }
    return 0;
}

/* error handler */
int benchmark_error_handler(CONN *conn, CB_DATA *packet, CB_DATA *cache, CB_DATA *chunk)
{
    if(conn)
    {
        //fprintf(stdout, "%s::%d error on conn[%s:%d] c_state:%d s_state:%d via %d\n", __FILE__, __LINE__, conn->local_ip, conn->local_port, conn->c_state, conn->s_state, conn->fd);
        return http_check_over(conn);
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
            ACCESS_LOGGER(logger, "timeout on conn[%s:%d] uri[%s] via %d status:%d", conn->local_ip, conn->local_port, cache->data, conn->fd, conn->status);
        }
        else
        {
            ACCESS_LOGGER(logger, "timeout on conn[%s:%d] via %d status:%d", conn->local_ip, conn->local_port, conn->fd, conn->status);
        }
        ntimeout++;
        return http_check_over(conn);
    }
    return -1;
}

/* ok handler */
int benchmark_ok_handler(CONN *conn)
{
    if(conn)
    {
        return http_request(conn);
    }
    return -1;
}

/* OOB data handler */
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

    while(ncurrent < concurrency)
    {
        id = ncurrent;
        if((conn = http_newconn(id, server_ip, server_port, server_is_ssl)) == NULL)
        {
            //ACCESS_LOGGER(logger, "ncurrent:%d", ncurrent);
            break;
        }
        else
        {
            //ACCESS_LOGGER(logger, "ncurrent:%d", ncurrent);
            ++ncurrent;
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
            if(sbase)sbase->stop(sbase);
            break;
        default:
            break;
    }
}

int main(int argc, char **argv)
{
    char *url = NULL, *urllist = NULL, line[HTTP_BUF_SIZE], *s = NULL, *p = NULL, ch = 0;
    struct hostent *hent = NULL;
    pid_t pid;
    int n = 0, log_level = 0;

    /* get configure file */
    while((ch = getopt(argc, argv, "vqpkdw:l:c:t:n:e:")) != -1)
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
            case 't':
                req_timeout = atoi(optarg);
                break;
            case 'p':
                is_post = 1;
                break;
            case 'v':
                is_verbosity = 1;
                break;
            case 'e':
                log_level = atoi(optarg);
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
                "Options:\n\t-c concurrency\n\t-n requests\n\t-w worker threads\n"
                "\t-t timeout (microseconds, default 1000000)\n"
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
        if(is_keepalive) p += sprintf(p, "Connection: KeepAlive\r\n");
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
        if(is_keepalive) p += sprintf(p, "Connection: KeepAlive\r\n");
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
    if((service = service_init()))
    {
        service->working_mode = 1;
        service->nprocthreads = workers;
        service->ndaemons = 0;
        service->niodaemons = 2;
        service->use_cond_wait = 1;
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
            running_status = 1;
            sbase->running(sbase, 0);
            //sbase->running(sbase, 3600);
            //sbase->running(sbase, 90000000);sbase->stop(sbase);
        }
        else fprintf(stderr, "add service failed, %s", strerror(errno));
    }
    sbase->clean(sbase);
    return 0;
}
