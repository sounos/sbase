#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>
#include "sbase.h"
#include "logger.h"
#include "message.h"
#include "evtimer.h"
#include "xssl.h"
#include "xmm.h"
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
            fprintf(stderr, "setrlimit %s cur[%ld] max[%ld] failed, errno:%d\n",
                    name, (long)rlim.rlim_cur, (long)rlim.rlim_max, errno);
        }
    }
    return ret;
}

/* event handler */
void sbase_event_handler(int event_fd, int flags, void *arg)
{
    SBASE *sbase = (SBASE *)arg;

    if(sbase)
    {
        event_del(&(sbase->event), E_WRITE);
    }
    return ;
}

/* set sbase log */
int sbase_set_log(SBASE *sbase, char *logfile)
{
    int ret = -1;
    if(sbase && logfile)
    {
        LOGGER_INIT(sbase->logger, logfile);
        ret = 0;
    }
    return ret;
}

/* set sbase log level  */
int sbase_set_log_level(SBASE *sbase, int level)
{
    int ret = -1;
    if(sbase && sbase->logger)
    {
        LOGGER_SET_LEVEL(sbase->logger, level);
        ret = 0;
    }
    return ret;
}


/* set evbase log */
int sbase_set_evlog(SBASE *sbase, char *evlogfile)
{
    int ret = -1;
    if(sbase && evlogfile)
    {
        sbase->evlogfile = evlogfile;
        ret = 0;
    }
    return ret;
}

/* set evbase log level */
int sbase_set_evlog_level(SBASE *sbase, int level)
{
    int ret = -1;
    if(sbase)
    {
        sbase->evlog_level = level;
        ret = 0;
    }
    return ret;
}

/* add service to sbase */
int sbase_add_service(SBASE *sbase, SERVICE  *service)
{
    int i = 0;

    if(sbase)
    {
        if(service && sbase->running_services < SB_SERVICE_MAX)
        {
            service->evbase = sbase->evbase;
            if(service->working_mode == WORKING_PROC) 
                service->evtimer = sbase->evtimer;
            else 
                service->evtimer = service->etimer;
            //service->evtimer = sbase->evtimer;
            service->sbase  = sbase;
            service->message_queue = sbase->message_queue;
            service->usec_sleep = sbase->usec_sleep;
            if(sbase->connections_limit == 0) sbase->connections_limit = SB_CONN_MAX;
            service->connections_limit = sbase->connections_limit;
            if(service->logger == NULL && sbase->logger) 
            {
                fprintf(stdout, "replace %s logger with sbase\n", service->service_name);
                service->logger = sbase->logger;
            }
            for(i = 0; i < SB_SERVICE_MAX; i++)
            {
                if(sbase->services[i] == NULL)
                {
                    sbase->services[i] = service;
                    sbase->running_services++;
                    break;
                }
            }
            return service->set(service);
        }
    }
    return -1;
}

/* sbase remove service */
void sbase_remove_service(SBASE *sbase, SERVICE *service)
{
    int i = 0;

    if(sbase && service)
    {
        for(i = 0; i < SB_SERVICE_MAX; i++)    
        {
            if(sbase->services[i] == service)
            {
                sbase->services[i] = NULL;
                sbase->running_services--;
                break;
            }
        }
    }
    return ;
}

/* sbase evtimer  handler */
void sbase_evtimer_handler(void *arg)
{
    SBASE *sbase = NULL;
    if((sbase = (SBASE *)arg))
    {
        sbase->running_status = 0;
    }
    return ;
}

/* run service */
int sbase_run_service(SBASE *sbase, SERVICE *service)
{
    if(sbase && service)
    {
        service->evbase = sbase->evbase;
        service->cond = sbase->cond;
        service->run(service);
        if(service->onrunning) service->onrunning(service);
    }
    return 0;
}
/* running all service */
int sbase_running(SBASE *sbase, int useconds)
{
    int ret = -1, i = -1, sec = 0, usec = 0;
    struct timeval tv = {0, 0};
    SERVICE *service = NULL;
    struct ip_mreq mreq;        
    pid_t pid = 0;

    if(sbase)
    {
        if(useconds > 0 )
        {
            sbase->evid = EVTIMER_ADD(sbase->evtimer, useconds,
                    &sbase_evtimer_handler, (void *)sbase);
        }
        if(sbase->nchilds > SB_THREADS_MAX) sbase->nchilds = SB_THREADS_MAX;
        //nproc
        if(sbase->nchilds > 0)
        {
            for(i = 0; i < sbase->nchilds; i++)
            {
                pid = fork();
                switch (pid)
                {
                    case -1:
                        exit(EXIT_FAILURE);
                        break;
                    case 0: //child process
                        if(setsid() == -1)
                            exit(EXIT_FAILURE);
                        goto running;
                        break;
                    default://parent
                        continue;
                        break;
                }
            }
            return 0;
        }
running:
        if((sbase->evbase   = evbase_init(0)) == NULL)
        {
            fprintf(stderr, "Initialize evbase failed, %s\n", strerror(errno));
            _exit(-1);
        }
        memset(&mreq, 0, sizeof(struct ip_mreq));        
        mreq.imr_multiaddr.s_addr = inet_addr("239.239.239.239");        
        mreq.imr_interface.s_addr = inet_addr("127.0.0.1");      
        if((sbase->cond = socket(AF_INET, SOCK_DGRAM, 0)) < 0
            || setsockopt(sbase->cond, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq,        
                sizeof(struct ip_mreq)) != 0)        
        {        
            //FATAL_LOGGER(sbase->logger, "new cond socket() failed, %s", strerror(errno));      
            _exit(-1);
        }
        /*
        if((sbase->cond = open(SB_COND_FILE, O_CREAT|O_RDWR, 0644)) < 0)
        {
            FATAL_LOGGER(sbase->logger, "open() condition file failed, %s", strerror(errno));      
            _exit(-1);
        }
        */
        event_set(&(sbase->event), sbase->cond, E_READ|E_PERSIST,
                    (void *)sbase, (void *)&sbase_event_handler);
        ret = sbase->evbase->add(sbase->evbase, &(sbase->event));
        //sbase->evbase->set_evops(sbase->evbase, EOP_POLL);
        //running services
        if(sbase->services)
        {
            for(i = 0; i < sbase->running_services; i++)
            {
                if((service = sbase->services[i]))
                {
                    sbase->run_service(sbase, service);
                }
            }
        }
        //running sbase 
        sbase->running_status = 1;
        if(sbase->usec_sleep > 1000000) sec = sbase->usec_sleep/1000000;
        usec = sbase->usec_sleep % 1000000;
        tv.tv_sec = sec;
        tv.tv_usec = usec;
        do
        {
            //running evbase 
            i = sbase->evbase->loop(sbase->evbase, 0, &tv);
            //check evtimer for heartbeat and timeout
            EVTIMER_CHECK(sbase->evtimer);
            //running message queue
            if(QMTOTAL(sbase->message_queue) > 0)
            {
                qmessage_handler(sbase->message_queue, sbase->logger);
            }
            //ACCESS_LOGGER(sbase->logger, "actived i:%d", i);
        }while(sbase->running_status);
        /* handler left message */
        if(QMTOTAL(sbase->message_queue) > 0)
            qmessage_handler(sbase->message_queue, sbase->logger);
        /* stop service */
        for(i = 0; i < sbase->running_services; i++)
        {
            if(sbase->services[i])
            {
                sbase->services[i]->stop(sbase->services[i]);
            }
        }
        ret = 0;
    }
    return ret;
}

void sbase_stop(SBASE *sbase)
{
    if(sbase && sbase->running_status)
    {
        //event_add(&(sbase->event), E_WRITE);
        sbase->running_status = 0;
        return ;
    }
}

/* clean sbase */
void sbase_clean(SBASE *sbase)
{
    int i = 0;

    if(sbase)
    {
        for(i = 0; i < sbase->running_services; i++)
        {
            if(sbase->services[i])
                sbase->services[i]->clean(sbase->services[i]);
        }
        event_destroy(&(sbase->event));
        if(sbase->cond > 0) close(sbase->cond);
        if(sbase->evtimer){EVTIMER_CLEAN(sbase->evtimer);}
        if(sbase->evbase){sbase->evbase->clean(sbase->evbase);}
        if(sbase->message_queue){qmessage_clean(sbase->message_queue);}
        if(sbase->logger){LOGGER_CLEAN(sbase->logger);}
#ifdef HAVE_SSL
        ERR_free_strings();
#endif
        xmm_free(sbase, sizeof(SBASE));
    }
    return ;
}

/* Initialize sbase */
SBASE *sbase_init()
{
    SBASE *sbase = NULL;
    if((sbase = (SBASE *)xmm_mnew(sizeof(SBASE))))
    {
        sbase->evtimer          = EVTIMER_INIT();
        sbase->message_queue    = qmessage_init();
        sbase->set_log		    = sbase_set_log;
        sbase->set_log_level	= sbase_set_log_level;
        sbase->set_evlog	    = sbase_set_evlog;
        sbase->set_evlog_level	= sbase_set_evlog_level;
        sbase->add_service	    = sbase_add_service;
        sbase->run_service	    = sbase_run_service;
        sbase->remove_service	= sbase_remove_service;
        sbase->running 		    = sbase_running;
        sbase->stop 		    = sbase_stop;
        sbase->clean 		    = sbase_clean;
#ifdef HAVE_SSL
        sbase->ssl_id           = SSL_library_init();
#endif
    }
    return sbase;
}
