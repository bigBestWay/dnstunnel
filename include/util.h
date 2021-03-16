#ifndef _UTIL_H_
#define _UTIL_H_

typedef struct
{
    char * ptr;
    int len;
}DataBuffer;

typedef enum
{
    IDLE,
    SYNC,
    BUSY
}SESSION_STATE;

void delay(long sec, long usec);

void getRand(void * p, int size);

void dumpHex(const char * buff, int len);

int memcpy_s(void *dst, int dstMax, const void *src, int srcLen);

int strcpy_s(void *dst, int dstMax, const void *src);

int writeFile(const char * path, const char * data, int len);

int readFile(const char * path, char * out, int len);

void xor(void * p, int len, unsigned short key);

DataBuffer * allocDataBuffer(int len);

void freeDataBuffer(DataBuffer * buffer);

#if DEBUG == 1
#define debug(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define debug(fmt, ...)
#endif

#endif