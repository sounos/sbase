#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include "mmblock.h"
#ifdef  HAVE_SSL
#include "xssl.h"
#endif
#include "xmm.h"
/* initialize() */
MMBLOCK *mmblock_init()
{
	MMBLOCK *mmblock = NULL;
	mmblock = (MMBLOCK *)xmm_mnew(sizeof(MMBLOCK));
    return mmblock;
}

/* incre() */
int mmblock_incre(MMBLOCK *mmblock, int incre_size)
{
	int size = 0, n = 0;

	if(mmblock && incre_size > 0)
	{
		size = mmblock->size + incre_size;
		n = size / MMBLOCK_BASE;
		if(size % MMBLOCK_BASE) ++n;
		size = n * MMBLOCK_BASE;
		//mmblock->data = (char *)realloc(mmblock->data, size);
		if((mmblock->data = (char *)xmm_resize(mmblock->data, mmblock->size, size)))
		{
			mmblock->end = mmblock->data + mmblock->ndata;
			mmblock->left = size - mmblock->ndata - 1;
			mmblock->size = size;
			return 0;
		}
		else
		{
			mmblock->end = mmblock->data = NULL;
			mmblock->left = mmblock->ndata = mmblock->size = 0;
		}
			
	}
	return -1;
}

/* check() */
int mmblock_check(MMBLOCK *mmblock)
{
	if(mmblock)
	{
		return mmblock_incre(mmblock, MMBLOCK_BASE);		
	}
	return -1;
}

/* recv() */
int mmblock_recv(MMBLOCK *mmblock, int fd, int flag)
{
	int n = -1;

	if(mmblock && fd > 0)
	{
        if(mmblock->left < MMBLOCK_MIN) mmblock_incre(mmblock, MMBLOCK_BASE);
		if(mmblock->data && mmblock->end && mmblock->left > 0
		&& (n = recv(fd, mmblock->end, mmblock->left, flag)) > 0)
		{
			mmblock->end += n;
			mmblock->ndata += n;
			mmblock->left -= n;		
            *(mmblock->end) = 0;
		}	
	}
	return n;
}

/* read() */
int mmblock_read(MMBLOCK *mmblock, int fd)
{
	int n = -1;

	if(mmblock && fd > 0)
	{
        if(mmblock->left < MMBLOCK_MIN) mmblock_incre(mmblock, MMBLOCK_BASE);
		if(mmblock->data && mmblock->end && mmblock->left > 0
		    && (n = recv(fd, mmblock->end, mmblock->left, MSG_DONTWAIT)) > 0)
		    //&& (n = read(fd, mmblock->end, mmblock->left)) > 0)
		{
			mmblock->ndata += n;
			mmblock->end += n;
			mmblock->left -= n;
            *(mmblock->end) = 0;
		}
	}
	return n;
}

/* SSL_read() */
int mmblock_read_SSL(MMBLOCK *mmblock, void *ssl)
{
	int n = -1;
	if(mmblock && ssl)
	{
        if(mmblock->left < MMBLOCK_MIN) mmblock_incre(mmblock, MMBLOCK_BASE);
#ifdef HAVE_SSL
		if(mmblock->data && mmblock->end && mmblock->left > 0
		&& (n = SSL_read(XSSL(ssl), mmblock->end, mmblock->left)) > 0)
		{
			mmblock->ndata += n;
			mmblock->end += n;
			mmblock->left -= n;
            *(mmblock->end) = 0;
		}
#endif
	}
	return n;
}

/* push() */
int mmblock_push(MMBLOCK *mmblock, char *data, int ndata)
{
	if(mmblock && data && ndata > 0)
	{
		if(mmblock->left < ndata) mmblock_incre(mmblock, ndata+1);
		if(mmblock->left > ndata && mmblock->data && mmblock->end)
		{
			memcpy(mmblock->end, data, ndata);
			mmblock->ndata += ndata;
			mmblock->end += ndata;
			mmblock->left -= ndata;
            *(mmblock->end) = 0;
			return ndata;
		}
	}
	return -1;
}

/* del() */
int mmblock_del(MMBLOCK *mmblock, int ndata)
{
	char *s = NULL, *p = NULL;

	if(mmblock && ndata > 0)
	{
		if(mmblock->ndata <= ndata)
		{
			mmblock->end = mmblock->data;
			mmblock->left = mmblock->size - 1;
			mmblock->ndata = 0;
		}
		else
		{
			p = mmblock->data;			
			s = mmblock->data + ndata;
			while(s < mmblock->end) *p++ = *s++;
			mmblock->end = p;
            *(mmblock->end) = 0;
			mmblock->left += ndata;
			mmblock->ndata -= ndata;
		}
		return 0;
	}
	return -1;
}

/* reset() */
void mmblock_reset(MMBLOCK *mmblock)
{
	if(mmblock)
	{
		if(mmblock->size > MMBLOCK_MAX)
        {

            xmm_free(mmblock->data, mmblock->size);
            mmblock->size = mmblock->ndata = mmblock->left = 0;
            mmblock->end = mmblock->data  = NULL;
        }
		else
		{
            //if(mmblock->data)memset(mmblock->data, 0, mmblock->size);
			mmblock->end = mmblock->data;
			mmblock->left = mmblock->size - 1;
			mmblock->ndata = 0;
		}
	}
	return ;
}

/* destroy */
void mmblock_destroy(MMBLOCK *mmblock)
{
	if(mmblock)
    {
        if(mmblock->data) xmm_free(mmblock->data, mmblock->size);
        mmblock->data = mmblock->end = NULL;
        mmblock->size = mmblock->ndata = mmblock->left = 0;
    }
	return ;
}

/* clean() */
void mmblock_clean(MMBLOCK *mmblock)
{
	if(mmblock)
    {
        if(mmblock->data) xmm_free(mmblock->data, mmblock->size);
        xmm_free(mmblock, sizeof(MMBLOCK));
    }
	return ;
}


#ifdef _DEBUG_MMBLOCK
#include <fcntl.h>
int main()
{
	char *s = "DSKALFJLSDJFLKASJFKLDAJFKLAKLkljklajfldkfmnklasnfkladsnk";
	MMBLOCK *mmblocks[40960];
	int i = 0, fd = -1, n = strlen(s);
    if((fd = open("/tmp/testfile", O_RDONLY)) > 0)
    {
        //initialize
        for(i = 0; i < 40960; i++)
        {
            if((mmblocks[i] = mmblock_init()))
            {
                mmblock_push(mmblocks[i], s, n);
                lseek(fd, 0, SEEK_SET);
                mmblock_read(mmblocks[i], fd);
            }
            //fprintf(stdout, "last_mmblock[%p]->ndata:%d\n", mmblocks[i], mmblocks[i]->ndata);
        }
        //while(1)sleep(1);
        //clean
        for(i = 0; i < 40960; i++)
        {
            if(mmblocks[i]) mmblock_clean(mmblocks[i]);
        }
        close(fd);
    }
	while(1)sleep(1);
	return 0;
}
//gcc -o vmm mmblock.c -D_DEBUG_MMBLOCK -DHAVE_MMAP -g && ./vmm
#endif
