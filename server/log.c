#include<stdio.h>
#include<time.h>
#include <stdarg.h>
#include<string.h>
#include "log.h"

static FILE * g_logfd = 0;

static int get_current_time(char * buffer, int size)
{
    time_t t;
    time(&t);
    struct tm *tmp_time = localtime(&t);
    return strftime(buffer, size, "%04Y-%02m-%02d %H:%M:%S", tmp_time);
}

void log_init()
{
    char filename[255] = "NDNS_server-";
    int len = strlen(filename);
    get_current_time(filename + len, sizeof(filename) - len);
    strcat(filename, ".log");
    g_logfd = fopen(filename, "w");
    if (g_logfd == NULL)
    {
        perror("fopen:");
    }
    setbuf(g_logfd, 0);
}

void log_print(const char * fmt, ...)
{
    char buffer[1024];
    int len = get_current_time(buffer, sizeof(buffer));
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buffer + len, sizeof(buffer) - len, fmt, ap);
    va_end(ap);
    fputs(buffer, g_logfd);
}
