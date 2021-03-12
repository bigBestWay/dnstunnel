#include <stdio.h>
#include <stdlib.h>
#include "../include/util.h"
#include <unistd.h>
#include "app.h"
#include "../include/udp.h"
#include "../include/cmd.h"
#include <string.h>
#include <pthread.h>
#include <ctype.h>
#include "session.h"
#include "log.h"

extern void * gateway(void * arg);
extern void startUI();

int main()
{
    session_init();
    log_init();
    setbuf(stdout, 0);

    pthread_t tid = 0;
    pthread_create(&tid, NULL, gateway, NULL);

    startUI();
    
    return 0;
}