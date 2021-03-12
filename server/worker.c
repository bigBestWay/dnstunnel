#include "../include/util.h"
#include "udp.h"
#include "dns.h"
#include "session.h"
#include "../include/cmd.h"
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include "app.h"
#include <pthread.h>
#include <sys/socket.h>
#include <stdio.h>
#include "worker.h"
/*
gateway 根据clientid将数据包转发到对应的子线程conn_handler处理，转发使用管道通信
下面2个变量是conn_handler才能使用
*/
__thread unsigned short g_tls_myclientid = 0; 
/* 每条线程一个专用时间戳 */
__thread time_t g_alive_timestamp = 0;

void * conn_handler(void * arg)
{
    struct WorkerArgs * workarg = (struct WorkerArgs *)arg;
    const int datafd = workarg->datafd;
    const int cmdfd = workarg->cmdfd;
    g_tls_myclientid = workarg->clientid;
    free(arg);

    char dataReq[65536];
    char dataRsp[1024*1024];
    g_alive_timestamp = time(0);
    while (1)
    {
        if (time(0) - g_alive_timestamp > 20)//超过1分钟没消息，退出线程
        {
            printf("session[%d] timeout\n", g_tls_myclientid);
            break;
        }
        
        int hascmd = wait_data(cmdfd, 0);
        int datalen = 0;
        if (hascmd == 1)
        {
            datalen = read(cmdfd, dataReq, sizeof(dataReq));
            if (datalen <= 0)
            {
                perror("read");
                continue;
            }

            debug("CLIENT[%d] cmd=%d come\n", g_tls_myclientid, ((struct CmdReq *)dataReq)->code);
        }
        else if(hascmd == 0)
        {
            ((struct CmdReq *)dataReq)->code = 0;
            datalen = 8;
        }
        else
        {
            debug("CLIENT[%d] conn_handler wait_data error!\n", g_tls_myclientid);
            continue;
        }
        
        int ret = server_send(datafd, dataReq, datalen);
        if(ret < 0)
        {
            perror("server_send");
        }
        else if(ret > 0)
        {
            time(&g_alive_timestamp);
        }

        if(hascmd)
        {
        recv:
            ret = server_recv(datafd, dataRsp, sizeof(dataRsp));
            if(ret > 0)
            {
                struct CmdReq * req = (struct CmdReq *)dataReq;
                struct CmdRsp * rsp = (struct CmdRsp *)dataRsp;
                if(rsp->sid != req->sid)
                    goto recv;

                char * output = parseCmdRsp(req, dataRsp, ret);
                DataBuffer * data = (DataBuffer *)malloc(sizeof(DataBuffer));
                data->ptr = output;
                data->len = strlen(output) + 1;
                if(write(cmdfd, &data, sizeof(data)) != sizeof(data))
                {
                    perror("parseCmdRsp write:");
                }
            }
            else
            {
                const char tmout[] = "\nNetwork Timeout.\n";
                DataBuffer * data = allocDataBuffer(sizeof(tmout));
                snprintf(data->ptr, data->len, "%s", tmout);
                if(write(cmdfd, &data, sizeof(data)) != sizeof(data))
                {
                    perror("parseCmdRsp write:");
                }
            }
        }
    }

    delete_session(g_tls_myclientid);
    close(cmdfd);
    close(datafd);
    return 0;
}
