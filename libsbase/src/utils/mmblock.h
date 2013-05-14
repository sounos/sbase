#ifndef _MMBLOCK_H_
#define _MMBLOCK_H_
#define MMBLOCK_BITS    1024
#ifndef __TYPEDEF__MMBLOCK
#define __TYPEDEF__MMBLOCK
typedef struct _MMBLOCK
{
    char *data;
    int  ndata;
    int  size;
    int  left;
    int  bits;
    char *end;
}MMBLOCK;
#endif
#define    MMBLOCK_BASE 	32768
//#define  MMBLOCK_BASE 	32768
//#define  MMBLOCK_BASE 	65536
//#define  MMBLOCK_BASE 	131072
//#define  MMBLOCK_BASE 	524288
#define  MMBLOCK_MIN 	    1024
#define  MMBLOCK_MAX 	    262144
//#define  MMBLOCK_MAX 	    1048576
/* initialize() */
MMBLOCK *mmblock_init();
/* recv() */
int mmblock_recv(MMBLOCK *mmblock, int fd, int flag);
/* read() */
int mmblock_read(MMBLOCK *mmblock, int fd);
/* SSL_read() */
int mmblock_read_SSL(MMBLOCK *mmblock, void *ssl);
/* push() */
int mmblock_push(MMBLOCK *mmblock, char *data, int ndata);
/* del() */
int mmblock_del(MMBLOCK *mmblock, int ndata);
/* reset() */
void mmblock_reset(MMBLOCK *mmblock);
/* destroy */
void mmblock_destroy(MMBLOCK *mmblock);
/* clean() */
void mmblock_clean(MMBLOCK *mmblock);
#define MMB(px) ((MMBLOCK *)px)
#define MMB_NDATA(x) (x.ndata)
#define MMB_SIZE(x) (x.size)
#define MMB_LEFT(x) (x.left)
#define MMB_DATA(x) (x.data)
#define MMB_END(x) (x.end)
#define MMB_RECV(x, fd, flag) mmblock_recv(&x, fd, flag)
#define MMB_READ(x, fd) mmblock_read(&x, fd)
#define MMB_READ_SSL(x, ssl) mmblock_read_SSL(&x, ssl)
#define MMB_PUSH(x, pdata, ndata) mmblock_push(&x, pdata, ndata)
#define MMB_DELETE(x, ndata) mmblock_del(&x, ndata)
#define MMB_RESET(x) mmblock_reset(&x)
#define MMB_DESTROY(x) mmblock_destroy(&x)
#define MMB_CLEAN(x) mmblock_clean(&x)
#endif
