#include <time.h>
#include <sched.h>
#include <unistd.h>
#include <sys/time.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "../include/util.h"
#include "../include/aes.h"

int writeFile(const char * path, const char * data, int len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU | S_IRGRP | S_IROTH);
    if(fd > 0)
    {
        int ret = write(fd, data, len);
        close(fd);
        return ret;
    }
    return fd;
}

int readFile(const char * path, char * out, int len)
{
    int fd = open(path, O_RDONLY);
    if (fd > 0)
    {
        off_t fileSize = lseek(fd, 0, SEEK_END);
        if (fileSize > len)
        {
            //printf("file %s size %lu exceed size %d\n", path, fileSize, len);
            close(fd);
            return 0;
        }
        lseek(fd, 0, SEEK_SET);
        int ret = read(fd, out, len);
        close(fd);
        return ret;
    }
    return fd;
}

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

int strcpy_s(void *dst, int dstMax, const void *src)
{
    int srclen = strlen(src);
    if (dstMax <= srclen)
    {
        abort();//debug
        return -1;
    }
    strcpy(dst, src);
    return srclen + 1;    
}

DataBuffer * allocDataBuffer(int len)
{
    DataBuffer * ret = (DataBuffer *)malloc(sizeof(DataBuffer));
    ret->ptr = (char *)malloc(len);
    ret->len = len;
    return ret;
}

void freeDataBuffer(DataBuffer * buffer)
{
    if(buffer)
    {
        free(buffer->ptr);
        buffer->ptr = 0;
        free(buffer);
    }
}
