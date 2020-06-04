#include "util.h"
#include <time.h>
#include <sched.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

void getRand(void * p, int size)
{
    int fd = open("/dev/urandom", 0);
    (void)read(fd, p, size);
    close(fd);
}

//使用select实现精确延时，微秒(百万分之一秒)
void delay(long sec, long usec)
{
    struct timeval t;
    t.tv_sec = sec;
    t.tv_usec = usec;
    select(0, NULL,NULL, NULL, &t);
}

void xor(const void * p, int len, unsigned short key)
{
    if (len % 2 != 0)
    {
        return;
    }
    
    unsigned short * s = (unsigned short *)p;
    while ((void *)s < p + len)
    {
        *s ^= key;
    }
    
}

void dumpHex(const char * buff, int len)
{
	for(int i = 0; i < len; ++i)
	{
		printf("%02x ", (unsigned char)buff[i]);
	}
	printf("\n");
}

int memcpy_s(void *dst, int dstMax, const void *src, int srcLen)
{
    if (srcLen > dstMax || dst == 0 || src == 0 || dstMax <=0 || srcLen <= 0)
    {
        abort();//debug
        return -1;
    }
    
    memcpy(dst, src, srcLen);
    return 0;
}
