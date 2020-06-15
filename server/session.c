#include "session.h"
#include "udp.h"
#include "app.h"
#include <pthread.h>
#include "../include/util.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#define MAX_SESSION_NUMBER 65536
static int g_session_number = 0;
static pthread_rwlock_t g_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static SessionEntry * g_sessionTable;

void session_init()
{
    if (pthread_rwlock_init(&g_rwlock, NULL) != 0)
    {
        perror("pthread_rwlock_init");
    }

    g_sessionTable = (SessionEntry *)malloc(sizeof(SessionEntry)*MAX_SESSION_NUMBER);
    memset(g_sessionTable, 0xff, sizeof(SessionEntry)*MAX_SESSION_NUMBER);
}

int add_session(unsigned short clientid, const SessionEntry * new_entry)
{
    pthread_rwlock_wrlock(&g_rwlock);
    if (g_sessionTable[clientid].cmdfd >= 0 || g_sessionTable[clientid].datafd >= 0)
    {
        pthread_rwlock_unlock(&g_rwlock);
        return -1;
    }
    ++g_session_number;
    memcpy_s(&g_sessionTable[clientid], sizeof(*new_entry), new_entry, sizeof(*new_entry));
    pthread_rwlock_unlock(&g_rwlock);
    return 0;
}

void delete_session(unsigned short clientid)
{
    pthread_rwlock_wrlock(&g_rwlock);
    close(g_sessionTable[clientid].cmdfd);
    close(g_sessionTable[clientid].datafd);
    g_sessionTable[clientid].cmdfd = -1;
    g_sessionTable[clientid].datafd = -1;
    --g_session_number;
    pthread_rwlock_unlock(&g_rwlock);
}

int get_data_fd(unsigned short clientid)
{
    int fd = -1;
    pthread_rwlock_rdlock(&g_rwlock);
    fd = g_sessionTable[clientid].datafd;
    pthread_rwlock_unlock(&g_rwlock);
    return fd;
}

int get_cmd_fd(unsigned short clientid)
{
    int fd = -1;
    pthread_rwlock_rdlock(&g_rwlock);
    fd = g_sessionTable[clientid].cmdfd;
    pthread_rwlock_unlock(&g_rwlock);
    return fd;
}

SessionList live_sessions()
{
    SessionList list = { {NULL}, 0};
    pthread_rwlock_rdlock(&g_rwlock);
    if (g_session_number != 0)
    {
        list.size = g_session_number;
        int index = 0;
        for (int i = 0; i < MAX_SESSION_NUMBER; i++)
        {
            if (g_sessionTable[i].cmdfd >= 0 && g_sessionTable[i].datafd >= 0)
            {
                list.list[index++] = &g_sessionTable[i];
            }
        }
    }
    pthread_rwlock_unlock(&g_rwlock);
    return list;
}
