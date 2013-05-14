#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "mutex.h"
#ifndef _MESSAGE_H
#define _MESSAGE_H
#ifdef __cplusplus
extern "C" {
#endif
/* MESSAGE DEFINE*/
#ifndef _TYPEDEF_MESSAGE
#define _TYPEDEF_MESSAGE
/* MESSAGE ACTION ID DEFINE */
#define MESSAGE_NEW_CONN        0x01
#define MESSAGE_NEW_SESSION     0x02
#define MESSAGE_INPUT           0x03
#define MESSAGE_OUTPUT          0x04
#define MESSAGE_BUFFER          0x05
#define MESSAGE_PACKET          0x06
#define MESSAGE_CHUNK           0x07
#define MESSAGE_DATA            0x08
#define MESSAGE_OVER            0x09
#define MESSAGE_SHUT            0x0a
#define MESSAGE_QUIT            0x0b
#define MESSAGE_TRANSACTION     0x0c
#define MESSAGE_TASK            0x0d
#define MESSAGE_HEARTBEAT       0x0e
#define MESSAGE_STATE           0x0f
#define MESSAGE_TIMEOUT         0x10
#define MESSAGE_STOP            0x11
#define MESSAGE_PROXY           0x12
#define MESSAGE_END             0x13
#define MESSAGE_SHUTOUT         0x14
#define MESSAGE_OUT             0x15
#define MESSAGE_FREE            0x16
#define MESSAGE_CHUNKIO         0x17
#define MESSAGE_MAX		        0x17
static char *messagelist[] = 
{
    "",
	"MESSAGE_NEW_CONN",
	"MESSAGE_NEW_SESSION",
	"MESSAGE_INPUT",
	"MESSAGE_OUTPUT",
	"MESSAGE_BUFFER",
	"MESSAGE_PACKET",
	"MESSAGE_CHUNK",
	"MESSAGE_DATA",
	"MESSAGE_OVER",
    "MESSAGE_SHUT",
	"MESSAGE_QUIT",
	"MESSAGE_TRANSACTION",
	"MESSAGE_TASK",
	"MESSAGE_HEARTBEAT",
	"MESSAGE_STATE",
	"MESSAGE_TIMEOUT",
	"MESSAGE_STOP",
	"MESSAGE_PROXY",
	"MESSAGE_END",
	"MESSAGE_SHUTOUT",
    "MESSAGE_OUT",
    "MESSAGE_FREE",
    "MESSAGE_CHUNKIO"
};
typedef struct _MESSAGE
{
    int             msg_id;
    int             index;
    int             fd;
    int             tid;
    void            *handler;
    void 	        *parent;
    void            *arg;
    struct _MESSAGE *next;
}MESSAGE;
#define QMSG_LINE_MAX 1024
#define QMSG_LINE_NUM 4096
#define QMSG_INIT_NUM 4096
//#define QMSG_INIT_NUM 16384
typedef struct _QMESSAGE
{
    int total;
    int qtotal;
    int nleft;
    int nlist;
    MESSAGE *left;
    MESSAGE *first;
    MESSAGE *last;
    MUTEX *mutex;
    MESSAGE *list[QMSG_LINE_MAX];
    MESSAGE pools[QMSG_INIT_NUM];
}QMESSAGE;
void *qmessage_init();
void qmessage_handler(void *q, void *logger);
void qmessage_push(void *q, int id, int index, int fd, int tid, void *parent, void *handler, void *arg);
void qmessage_clean(void *q);
/* Initialize message */
#define QMTOTAL(q) ((q)?(((QMESSAGE *)q)->total):0)
#define QNLEFT(q) ((q)?(((QMESSAGE *)q)->nleft):0)
#define MESSAGE_SIZE    sizeof(MESSAGE)
#endif
#ifdef __cplusplus
 }
#endif
#endif
