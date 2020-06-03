#ifndef _UTIL_H_
#define _UTIL_H_

typedef struct
{
    const char * ptr;
    int len;
}DataBuffer;

void delay(long sec, long usec);

void getRand(void * p, int size);

void xor(const void * p, int len, unsigned short key);

void get_sys_nameserver(char * server, int len);

void dumpHex(const char * buff, int len);

int memcpy_s(void *dst, int dstMax, const void *src, int srcLen);
#endif