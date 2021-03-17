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

static void banner()
{
    const char msg[] = 
    "         88                                                                              88\n" 
    "         88                         ,d                                                   88\n"
    "         88                         88                                                   88\n"
    " ,adPPYb,88 8b,dPPYba,  ,adPPYba, MM88MMM 88       88 8b,dPPYba,  8b,dPPYba,   ,adPPYba, 88\n" 
    "a8\"    `Y88 88P'   `\"8a I8[    \"\"   88    88       88 88P'   `\"8a 88P'   `\"8a a8P_____88 88\n" 
    "8b       88 88       88  `\"Y8ba,    88    88       88 88       88 88       88 8PP\"\"\"\"\"\"\" 88\n" 
    "\"8a,   ,d88 88       88 aa    ]8I   88,   \"8a,   ,a88 88       88 88       88 \"8b,   ,aa 88\n" 
    " `\"8bbdP\"Y8 88       88 `\"YbbdP\"'   \"Y888  `\"YbbdP'Y8 88       88 88       88  `\"Ybbd8\"' 88";
    printf("%s  v1.1\n", msg);
}

int main()
{
    banner();

    session_init();
    log_init();
    setbuf(stdout, 0);

    pthread_t tid = 0;
    pthread_create(&tid, NULL, gateway, NULL);

    startUI();
    
    return 0;
}