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
#include "zlib.h"
#include "session.h"
#include <arpa/inet.h>

static void UI_waiting()
{
    static char ch = '|';
    //rewind(stdout);
    //ftruncate(1, 0);
    switch (ch)
    {
    case '|':
        ch = '/';
        break;
	case '/':
		ch = '-';
		break;
    case '-':
        ch = '\\';
        break;
    case '\\':
        ch = '|';
    default:
        break;
    }
    write(1, &ch, 1);
}

void startUI()
{
    int currentSession = -1;
    while (1)
    {
        SessionList sessionList = live_sessions();
        if (sessionList.size == 0)
        {
            UI_waiting();
            delay(0, 1000);
            fputs("\033[1D", stdout);
            continue;
        }

        if (currentSession < 0) //如果未选择session，默认指定第一个
        {
            currentSession = sessionList.list[0]->clientid;
        }
        else
        {
            int valid = 0;
            for (int i = 0; i < sessionList.size; i++)
            {
                if (sessionList.list[i]->clientid == currentSession)
                {
                    valid = 1;
                    break;
                }
            }

            if (!valid)
            {
                printf("session %d not valid\n", currentSession);
                currentSession = sessionList.list[0]->clientid;
            }
        }
        
        printf("Session[%d]#", currentSession);
        char buffer[65536] = {0};
        read(0, buffer, sizeof(buffer));
        //最多5个参数
        const char * argv[6] = {0};
        int argc1 = 0, argc2 = 0;
        argc1 = parseCmdLine(buffer, argv);//包括了命令自身
        if (argc1 == 0)
        {
            continue;
        }
        
        int result = findCmd(argv[0], &argc2);
        if (result < 0)
        {
            usage();
            continue;
        }
        
        if (argc1 - 1 < argc2)
        {
            help(result);
            continue;
        }

        if (result == 0)//session管理命令
        {
            if (strcmp(argv[1], "list") == 0)
            {
                SessionList sessionList = live_sessions();
                printf("clientid\tip\thostname\t\n");
                const char * fmt = "%d\t%s\t%s\n";
                for (int i = 0; i < sessionList.size; i++)
                {
                    struct in_addr addr;
                    addr.s_addr = sessionList.list[i]->ip;
                    char * ipv4 = inet_ntoa(addr);
                    printf(fmt, sessionList.list[i]->clientid, ipv4, sessionList.list[i]->hostname);
                }
                continue;
            }
            else if(strcmp(argv[1], "timeout") == 0)
            {
                if(argc1 == 2)//查询
                {
                    result = INNER_CMD_QUERY_SESSION_TM;
                }
                else if(argc1 == 3)
                {
                    result = INNER_CMD_SET_SESSION_TM;
                }
            }
            else
            {
                int arg = atoi(argv[1]);
                currentSession = arg;
                continue;
            }
        }
                
        unsigned char code = result;
        int len = buildCmdReq(code, argv, argc1, buffer, sizeof(buffer));
        if (len <= 0)
        {
            continue;
        }
        
        int cmdfd = get_cmd_fd(currentSession);
        if (cmdfd < 0)
        {
            perror("UI get_cmd_fd");
            continue;
        }
        
        len = write(cmdfd, buffer, len);
        if (len <=0 )
        {
            perror("UI write");
            continue;
        }

        if(code == SERVER_CMD_SAFEEXIT)
        {
            //无回显
            continue;
        }

        while(wait_data(cmdfd, 0) == 0)
        {
            UI_waiting();
            delay(0, 1000);
            fputs("\033[1D", stdout);
        }
        fputs("\033[1D", stdout);

        DataBuffer * rspData = 0;
        len = read(cmdfd, &rspData, sizeof(rspData));
        if (len == sizeof(rspData))
        {
            printf("%s", rspData->ptr);
            freeDataBuffer(rspData);
        }
        else
        {
            perror("UI read:");
        }
    }
}