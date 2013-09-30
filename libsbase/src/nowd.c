#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <locale.h>
#include <sys/resource.h>
#include <sbase.h>
#include "iniparser.h"
#include "http.h"
#include "stime.h"
#include "logger.h"
static int is_detail = 0;
static SBASE *sbase = NULL;
static SERVICE *service = NULL;
static dictionary *dict = NULL;
void *logger = NULL;
#define HTTP_VIEW_SIZE 65536
#define XHTTPD_VERSION "0.0.1"
#define LL(xxx) ((long long int)xxx)
#define http_default_charset "utf-8"
int xhttpd_index_view(CONN *conn, HTTP_REQ *http_req, char *dir, char *path);
int nowd_packet_reader(CONN *conn, CB_DATA *buffer)
{
    //return xhttpd_index_view(conn, NULL, "/data", "/");
    fprintf(stdout, "%s", buffer->data);
    return buffer->ndata;
}

/* welcome handler */
int nowd_welcome_handler(CONN *conn)
{
    SESSION session = {0};
    if(conn)
    {
        memset(&session, 0, sizeof(SESSION));
        session.packet_type = PACKET_PROXY;
        if(service->is_use_SSL) session.flags |= SB_USE_SSL;
        session.timeout = httpd_proxy_timeout;
        session.exchange_handler = &nowd_exchange_handler;
        if((new_conn = service->newproxy(service, conn, -1, -1, "23.22.248.181", 8253, &session)))
        {
            //new_conn->start_cstate(new_conn);
            return 0;
        }

    }
    return 0;
}

int nowd_packet_handler(CONN *conn, CB_DATA *packet)
{
	if(conn)
    {
        /*HTTP_REQ http_req = {0};
        char *p = NULL, *end = NULL;
        p = packet->data;
        end = packet->data + packet->ndata;
        return xhttpd_index_view(conn, NULL, "/", "/"); */
        int x = 0, n = 0, keepalive = 0; 
        if(strcasestr(packet->data, "Keep-Alive")) keepalive = 1;
        char buf[4096], *s = "{'data':{'action':'','alert':'hello','title':'starter'}}";x = strlen(s);
        if(keepalive)
        {
            n = sprintf(buf, "HTTP/1.0 200 OK\r\nConnection: Keep-Alive\r\nContent-Length:%d\r\n\r\n%s", x, s);conn->push_chunk(conn, buf, n); 
        }
        else
        {
            n = sprintf(buf, "HTTP/1.0 200 OK\r\nContent-Length:%d\r\n\r\n%s", x, s);conn->push_chunk(conn, buf, n); 

        }
        if(keepalive == 0) conn->over(conn); 
        /*
        */
        return 0;
        /*
        */
		//return conn->push_chunk((CONN *)conn, ((CB_DATA *)packet)->data, packet->ndata);
    }
    return -1;
}

int nowd_data_handler(CONN *conn, CB_DATA *packet, CB_DATA *cache, CB_DATA *chunk)
{
    return -1;
}

int nowd_oob_handler(CONN *conn, CB_DATA *oob)
{
    if(conn && conn->push_chunk)
    {
        conn->push_chunk((CONN *)conn, ((CB_DATA *)oob)->data, oob->ndata);
        return oob->ndata;
    }
    return -1;
}

static void nowd_stop(int sig){
    switch (sig) {
        case SIGINT:
        case SIGTERM:
            fprintf(stderr, "lhttpd server is interrupted by user.\n");
            if(sbase)sbase->stop(sbase);
            break;
        default:
            break;
    }
}

/* Initialize from ini file */
int sbase_initialize(SBASE *sbase, char *conf)
{
	char *s = NULL, *p = NULL, *cacert_file = NULL, *privkey_file = NULL;
	if((dict = iniparser_new(conf)) == NULL)
	{
		fprintf(stderr, "Initializing conf:%s failed, %s\n", conf, strerror(errno));
		_exit(-1);
	}
	/* SBASE */
	sbase->nchilds = iniparser_getint(dict, "SBASE:nchilds", 0);
	sbase->connections_limit = iniparser_getint(dict, "SBASE:connections_limit", SB_CONN_MAX);
	sbase->usec_sleep = iniparser_getint(dict, "SBASE:usec_sleep", SB_USEC_SLEEP);
	sbase->set_log(sbase, iniparser_getstr(dict, "SBASE:logfile"));
    sbase->set_log_level(sbase, iniparser_getint(dict, "SBASE:log_level", 0));
	sbase->set_evlog(sbase, iniparser_getstr(dict, "SBASE:evlogfile"));
	/* NOWD */
	if((service = service_init()) == NULL)
	{
		fprintf(stderr, "Initialize service failed, %s", strerror(errno));
		_exit(-1);
	}
	service->family = iniparser_getint(dict, "NOWD:inet_family", AF_INET);
	service->sock_type = iniparser_getint(dict, "NOWD:socket_type", SOCK_STREAM);
	service->ip = iniparser_getstr(dict, "NOWD:service_ip");
	service->port = iniparser_getint(dict, "NOWD:service_port", 80);
	service->working_mode = iniparser_getint(dict, "NOWD:working_mode", WORKING_PROC);
	service->service_type = iniparser_getint(dict, "NOWD:service_type", C_SERVICE);
	service->service_name = iniparser_getstr(dict, "NOWD:service_name");
	service->nprocthreads = iniparser_getint(dict, "NOWD:nprocthreads", 1);
	service->niodaemons = iniparser_getint(dict, "NOWD:niodaemons", 1);
	service->ndaemons = iniparser_getint(dict, "NOWD:ndaemons", 0);
    //service->session.packet_type= PACKET_CUSTOMIZED;
    service->session.packet_type=iniparser_getint(dict, "NOWD:packet_type",PACKET_DELIMITER);
    if((service->session.packet_delimiter = iniparser_getstr(dict, "NOWD:packet_delimiter")))
    {
        p = s = service->session.packet_delimiter;
        while(*p != 0 )
        {
            if(*p == '\\' && *(p+1) == 'n')
            {
                *s++ = '\n';
                p += 2;
            }
            else if (*p == '\\' && *(p+1) == 'r')
            {
                *s++ = '\r';
                p += 2;
            }
            else
                *s++ = *p++;
        }
        *s++ = 0;
        service->session.packet_delimiter_length = strlen(service->session.packet_delimiter);
    }
	service->session.buffer_size = iniparser_getint(dict, "NOWD:buffer_size", SB_BUF_SIZE);
	service->session.welcome_handler = &nowd_welcome_handler;
	service->session.packet_reader = &nowd_packet_reader;
	service->session.packet_handler = &nowd_packet_handler;
	service->session.data_handler = &nowd_data_handler;
    service->session.oob_handler = &nowd_oob_handler;
    cacert_file = iniparser_getstr(dict, "NOWD:cacert_file");
    privkey_file = iniparser_getstr(dict, "NOWD:privkey_file");
    if(cacert_file && privkey_file && iniparser_getint(dict, "NOWD:is_use_SSL", 0))
    {
        service->is_use_SSL = 1;
        service->cacert_file = cacert_file;
        service->privkey_file = privkey_file;
    }
    if((p = iniparser_getstr(dict, "NOWD:logfile")))
    {
        service->set_log(service, p);
        service->set_log_level(service, iniparser_getint(dict, "NOWD:log_level", 0));
    }
	/* server */
	fprintf(stdout, "Parsing for server...\n");
	return sbase->add_service(sbase, service);
}

int main(int argc, char **argv)
{
    pid_t pid;
    char *conf = NULL, *p = NULL, ch = 0;
    int is_daemon = 0;

    /* get configure file */
    while((ch = getopt(argc, argv, "c:d")) != (char)-1)
    {
        if(ch == 'c') conf = optarg;
        else if(ch == 'd') is_daemon = 1;
    }
    if(conf == NULL)
    {
        fprintf(stderr, "Usage:%s -d -c config_file\n", argv[0]);
        _exit(-1);
    }
    /* locale */
    setlocale(LC_ALL, "C");
    /* signal */
    signal(SIGTERM, &nowd_stop);
    signal(SIGINT,  &nowd_stop);
    signal(SIGHUP,  SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
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
    setrlimiter("RLIMIT_NOFILE", RLIMIT_NOFILE, 10240);
    if((sbase = sbase_init()) == NULL)
    {
        exit(EXIT_FAILURE);
        return -1;
    }
    fprintf(stdout, "Initializing from configure file:%s\n", conf);
    /* Initialize sbase */
    if(sbase_initialize(sbase, conf) != 0 )
    {
        fprintf(stderr, "Initialize from configure file failed\n");
        exit(EXIT_FAILURE);
        return -1;
    }
    fprintf(stdout, "Initialized successed\n");
    if(service->sock_type == SOCK_DGRAM 
            && (p = iniparser_getstr(dict, "NOWD:multicast")))
    {
        if(service->add_multicast(service, p) != 0)
        {
            fprintf(stderr, "add multicast:%s failed, %s", p, strerror(errno));
            exit(EXIT_FAILURE);
            return -1;
        }
        p = "224.1.1.168";
        if(service->add_multicast(service, p) != 0)
        {
            fprintf(stderr, "add multicast:%s failed, %s", p, strerror(errno));
            exit(EXIT_FAILURE);
            return -1;
        }

    }
    sbase->running(sbase, 0);
    //sbase->running(sbase, 60000000); sbase->stop(sbase);
    //sbase->running(sbase, 90000000);sbase->stop(sbase);
    sbase->clean(sbase);
    if(dict)iniparser_free(dict);
    return 0;
}
