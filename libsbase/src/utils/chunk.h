#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/mman.h>
#ifdef HAVE_SSL
#include "xssl.h"
#endif
#ifndef _CHUNK_H
#define _CHUNK_H
#ifdef __cplusplus
extern "C" {
#endif
#define CHUNK_MEM   0x02
#define CHUNK_FILE  0x04
#define CHUNK_ALL  (CHUNK_MEM | CHUNK_FILE)
#define CHUNK_BLOCK_MAX         524288
//#define CHUNK_BLOCK_MAX       1024
#define MMAP_PAGE_SIZE          4096
//#define CHUNK_BLOCK_MAX       1048576
#ifndef MMAP_CHUNK_SIZE
//#define MMAP_CHUNK_SIZE       4096
#define MMAP_CHUNK_SIZE         1048576
//#define MMAP_CHUNK_SIZE       2097152
//#define MMAP_CHUNK_SIZE       2097152
//#define MMAP_CHUNK_SIZE       3145728
//#define MMAP_CHUNK_SIZE       4194304
//#define MMAP_CHUNK_SIZE       8388608 
#endif
#ifndef CHUNK_BLOCK_SIZE
#define CHUNK_BLOCK_SIZE        4096
#endif
#define CHUNK_STATUS_ON         0x01
#define CHUNK_STATUS_OVER       0x02
#ifndef __TYPEDEF__CHUNK
#define __TYPEDEF__CHUNK
#define CHUNK_FILE_NAME_MAX     256
typedef struct _CHUNK
{
    char *data;
    int  ndata;
    int  status;
    int  bsize;
    int  type;
    int  fd;
    int  bits;
    off_t size;
    off_t offset;
    off_t left;
    off_t mmleft;
    off_t mmoff;
    char *mmap;
    char *end;
    char filename[CHUNK_FILE_NAME_MAX];
}CHUNK;
#endif
typedef struct _CHUNK * PCHUNK;
#define CHK(ptr) ((CHUNK *)ptr)
#define CHK_DATA(chk) (chk.data)
#define CHK_NDATA(chk) (chk.ndata)
#define CHK_LEFT(chk) (chk.left)
#define CHK_END(chk) (chk.end)
#define CHK_TYPE(chk) (chk.type)
#define CHK_FD(chk) (chk.fd)
#define CHK_FILENAME(chk) (chk.filename)
#define CHK_SIZE(chk) (chk.size)
#define CHK_BSIZE(chk) (chk.bsize)
#define CHK_OFFSET(chk) (chk.offset)
#define CHK_STATUS(chk) (chk.status)
/* initialize chunk */
CHUNK *chunk_init();
/* set/initialize chunk mem */
int chunk_set_bsize(void *chunk, int len);
/* set/initialize chunk mem */
int chunk_mem(void *chunk, int len);
/* reading to chunk */
int chunk_read(void *chunk, int fd);
/* reading to chunk with SSL */
int chunk_read_SSL(void *chunk, void *ssl);
/* writting from chunk */
int chunk_write(void *chunk, int fd);
/* chunk sendto */
int chunk_sendto(void *chunk, int fd, char *ip, int port);
/* writting from chunk with SSL */
int chunk_write_SSL(void *chunk, void *ssl);
/* fill chunk memory */
int chunk_mem_fill(void *chunk, void *data, int ndata);
/* copy to chunk */
int chunk_mem_copy(void *chunk, void *data, int ndata);
/* read data to file from fd */
int chunk_read_to_file(void *chunk, int fd);
/* push data to file */
int chunk_read_to_file_SSL(void *chunk, void *ssl);
/* write from file */
int chunk_write_from_file(void *chunk, int fd);
/* write from file with SSL */
int chunk_write_from_file_SSL(void *chunk, void *ssl);
/* chunk file fill */
int chunk_file_fill(void *chunk, char *data, int ndata);
/* chunk reset */
void chunk_reset(void *chunk);
/* chunk destroy */
void chunk_destroy(void *chunk);
/* clean chunk */
void chunk_clean(void *chunk);
/* initialize chunk file */
int chunk_file(void *chunk, char *file, off_t offset, off_t len);
#define CHUNK_STATUS(ptr) ((CHK(ptr)->left == 0)?CHUNK_STATUS_OVER:CHUNK_STATUS_ON)
#define CHUNK_READ(ptr, fd) ((CHK(ptr)->type == CHUNK_MEM)?chunk_read(ptr, fd):chunk_read_to_file(ptr, fd))
#define CHUNK_READ_SSL(ptr, ssl) ((CHK(ptr)->type == CHUNK_MEM)?chunk_read_SSL(ptr, ssl):chunk_read_to_file_SSL(ptr, ssl))
#define CHUNK_WRITE(ptr, fd) ((CHK(ptr)->type == CHUNK_MEM)?chunk_write(ptr, fd):chunk_write_from_file(ptr, fd))
#define CHUNK_SENDTO(ptr, fd, ip, port) chunk_sendto(ptr, fd, ip, port)
#define CHUNK_WRITE_SSL(ptr, ssl) ((CHK(ptr)->type == CHUNK_MEM)?chunk_write_SSL(ptr, ssl):chunk_write_from_file_SSL(ptr, ssl))
#define CHUNK_FILL(ptr, data, ndata) ((CHK(ptr)->type == CHUNK_MEM)?chunk_mem_fill(ptr, data, ndata):chunk_file_fill(ptr, data, ndata))
#ifdef __cplusplus
 }
#endif
#endif
