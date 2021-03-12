#ifndef _H_WORKER_
#define _H_WORKER_

void * conn_handler(void * arg);

struct WorkerArgs
{
    unsigned short clientid;
    int datafd;
    int cmdfd;
};

#endif