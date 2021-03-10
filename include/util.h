#ifndef _UTIL_H_
#define _UTIL_H_

typedef struct
{
    char * ptr;
    int len;
}DataBuffer;

unsigned short crc16(const void *buf, int size);

void delay(long sec, long usec);

void getRand(void * p, int size);

void xor(const void * p, int len, unsigned short key);

void dumpHex(const char * buff, int len);

int memcpy_s(void *dst, int dstMax, const void *src, int srcLen);

int strcpy_s(void *dst, int dstMax, const void *src);

int writeFile(const char * path, const char * data, int len);

int readFile(const char * path, char * out, int len);

DataBuffer * allocDataBuffer(int len);

void freeDataBuffer(DataBuffer * buffer);

#if DEBUG == 1
#define debug(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define debug(fmt, ...)
#endif

#endif