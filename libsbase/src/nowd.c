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
static SBASE *sbase = NULL;
static SERVICE *nowd = NULL;
static dictionary *dict = NULL;
void *logger = NULL;
int nowd_packet_reader(CONN *conn, CB_DATA *buffer)
{
    fprintf(stdout, "%s", buffer->data);
    return buffer->ndata;
}

int nowd_exchange_handler(CONN *conn, CB_DATA *exchange)
{
    char path[1024];
    int fd = 0, n = 0;
    if(conn)
    {
        n = sprintf(path, "/tmp/%s-%d-%d.exchange", conn->remote_ip, conn->remote_port, conn->fd);
        if((fd = open(path, O_CREAT|O_WRONLY|O_APPEND, 0644)) > 0)
        {
            n = write(fd, exchange->data, exchange->ndata);
            fprintf(stdout, "exchange %d bytes from %s:%d\n", exchange->ndata, conn->remote_ip, conn->remote_port);
            close(fd);
        }
    }
    return 0;
}

/* welcome handler */
int nowd_welcome_handler(CONN *conn)
{
    SESSION session = {0};
    if(conn)
    {

        memset(&session, 0, sizeof(SESSION));
        session.packet_type = PACKET_PROXY;
        //if(service->is_use_SSL) 
        session.flags |= SB_USE_SSL;
        session.exchange_handler = &nowd_exchange_handler;
        //fprintf(stdout, "%s:%d\n", conn->remote_ip, conn->remote_port);
        char *ip = "54.85.13.159";int port = 443;
        //char *ip = "54.85.13.159";int port = 8253;
        if((nowd->newproxy(nowd, conn, -1, -1, ip, port, &session)))
        {
            fprintf(stdout, "proxy{%s:%d to %s:%d}\n", conn->remote_ip, conn->remote_port, ip, port);
            return 0;
        }
	/*
	char *s = "{\"time\":\"2013-10-01T07:01:27.556Z\",\"oauth_key\":\"3LN4UQc1WaKM9tDFMJvreYWJzVvA3rGmMe4XhmAq\",\"data\":{\"alert\":\"gogogogooooo\",\"push_hash\":\"ab6a85df66766e18c015ffce33f1e4ba\"}}";
	conn->push_chunk(conn, s, strlen(s));
	*/
    }
    return 0;
}
static void nowd_stop(int sig){
    switch (sig) {
        case SIGINT:
        case SIGTERM:
            fprintf(stderr, "nowd server is interrupted by user.\n");
            if(sbase)sbase->stop(sbase);
            break;
        default:
            break;
    }
    return ;
}

/* Initialize from ini file */
int sbase_initialize(SBASE *sbase, char *conf)
{
	char *p = NULL, *cacert_file = NULL, *privkey_file = NULL;

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
	sbase->set_log_level(sbase, iniparser_getint(dict, "SBASE:log_level", 2));
	sbase->set_evlog(sbase, iniparser_getstr(dict, "SBASE:evlogfile"));
	/* NOWD */
	if((nowd = service_init()) == NULL)
	{
		fprintf(stderr, "Initialize service failed, %s", strerror(errno));
		_exit(-1);
	}
	nowd->family = iniparser_getint(dict, "NOWD:inet_family", AF_INET);
	nowd->sock_type = iniparser_getint(dict, "NOWD:socket_type", SOCK_STREAM);
	nowd->ip = iniparser_getstr(dict, "NOWD:service_ip");
	nowd->port = iniparser_getint(dict, "NOWD:service_port", 80);
	nowd->working_mode = iniparser_getint(dict, "NOWD:working_mode", WORKING_PROC);
	nowd->service_type = iniparser_getint(dict, "NOWD:service_type", S_SERVICE);
	nowd->service_name = iniparser_getstr(dict, "NOWD:service_name");
	nowd->nprocthreads = iniparser_getint(dict, "NOWD:nprocthreads", 8);
	nowd->niodaemons = iniparser_getint(dict, "NOWD:niodaemons", 1);
	nowd->ndaemons = iniparser_getint(dict, "NOWD:ndaemons", 0);
	nowd->session.packet_type=iniparser_getint(dict, "NOWD:packet_type", PACKET_PROXY);
	nowd->session.buffer_size = iniparser_getint(dict, "NOWD:buffer_size", SB_BUF_SIZE);
	nowd->session.welcome_handler = &nowd_welcome_handler;
	nowd->session.exchange_handler = &nowd_exchange_handler;
	cacert_file = iniparser_getstr(dict, "NOWD:cacert_file");
	privkey_file = iniparser_getstr(dict, "NOWD:privkey_file");
	if(cacert_file && privkey_file && iniparser_getint(dict, "NOWD:is_use_SSL", 0))
	{
		nowd->is_use_SSL = 1;
		nowd->cacert_file = cacert_file;
		nowd->privkey_file = privkey_file;
	}
	if((p = iniparser_getstr(dict, "NOWD:logfile")))
	{
		nowd->set_log(nowd, p);
		nowd->set_log_level(nowd, iniparser_getint(dict, "NOWD:log_level", 0));
	}
	/* server */
	fprintf(stdout, "Parsing for server...\n");
	return sbase->add_service(sbase, nowd);
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
    sbase->running(sbase, 0);
    //sbase->running(sbase, 60000000); sbase->stop(sbase);
    //sbase->running(sbase, 90000000);sbase->stop(sbase);
    sbase->clean(sbase);
    if(dict)iniparser_free(dict);
    return 0;
}
