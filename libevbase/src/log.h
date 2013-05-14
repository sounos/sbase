#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#ifndef _LOG_H
#define _LOG_H
static char *_ymonths[]= {
	"Jan", "Feb", "Mar",
	"Apr", "May", "Jun",
	"Jul", "Aug", "Sep",
	"Oct", "Nov", "Dec"};
#define LOG_HEADER(out)									\
{											\
	struct timeval tv;								\
	time_t timep;  									\
	struct tm *p = NULL;								\
	gettimeofday(&tv, NULL);							\
	time(&timep); 									\
	p = localtime(&timep);								\
	fprintf(out, "[%02d/%s/%04d:%02d:%02d:%02d +%06u] #%u# %s::%d ",		\
			p->tm_mday, _ymonths[p->tm_mon], (1900+p->tm_year), p->tm_hour,	\
			p->tm_min, p->tm_sec, (unsigned int)tv.tv_usec, 			\
			(unsigned int)getpid(), __FILE__, __LINE__);\
}
#ifndef DEBUG_LOG
#ifdef _DEBUG										
#define DEBUG_LOG(format...)								\
{											\
	LOG_HEADER(stdout);								\
	fprintf(stdout, "\"DEBUG:");							\
	fprintf(stdout, format);							\
	fprintf(stdout, "\"\n");							\
	fflush(stdout);									\
}											
#else											
#define  DEBUG_LOG(format...)
#endif											
#endif

#define FATAL_LOG(format...)								\
{											\
	LOG_HEADER(stderr);								\
	fprintf(stderr, "\"FATAL:");							\
	fprintf(stderr, format);							\
	fprintf(stderr, "\"\n");							\
	fflush(stdout);									\
}
#define WARN_LOG(format...)								\
{											\
	LOG_HEADER(stdout);								\
	fprintf(stdout, "\"WARN:");							\
	fprintf(stdout, format);							\
	fprintf(stdout, "\"\n");							\
}

//#define SHOW_LOG(format...)								
#define SHOW_LOG(format...)								\
{											\
	LOG_HEADER(stdout);                                                             \
        fprintf(stdout, "\"DEBUG:");                                                    \
        fprintf(stdout, format);                                                        \
        fprintf(stdout, "\"\n");                                                        \
	fflush(stdout);									\
}
#endif
