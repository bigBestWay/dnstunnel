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
#include "log.h"
#include "zlib.h"
#include <arpa/inet.h>
/*
gateway 根据clientid将数据包转发到对应的子线程conn_handler处理，转发使用管道通信
下面2个变量是conn_handler才能使用
*/
__thread unsigned short g_tls_myclientid = 0; 
/* 每条线程一个专用时间戳 */
__thread time_t g_alive_timestamp = 0;
/* 超时阈值，可通过命令设置 */
__thread int g_conn_tmout_threshold = 30;

/*
    返回一个用于屏幕显示的字符串指针
*/
char * parseCmdRsp(const struct CmdReq * req, const char * data, int len)
{
    struct CmdRsp * rsp = (struct CmdRsp *)data;
    unsigned int datalen = ntohl(rsp->datalen);
    if (datalen > len)
    {
        printf("\nRecv CmdRsp length error\n");
        return 0;
    }

    char * msg = (char *)malloc(255);
    memset(msg, 0, 255);

    if (rsp->errNo == CUSTOM_ERRNO)
    {
        rsp->data[datalen] = 0;
        snprintf(msg, 255, "Remote error: %s.\n", rsp->data);
    }
    else if(rsp->errNo != 0)
    {
        const char * errMsg = strerror(rsp->errNo);
        snprintf(msg, 255, "Remote error: %s.\n", errMsg);
    }
    else
    {
        if (rsp->flag == 1)
        {
            unsigned long plainLen = datalen*10;
            char * plain = (char *)malloc(plainLen + 1);
            int ret = uncompress((Bytef *)plain, &plainLen, (const Bytef *)rsp->data, datalen);
            if (ret == Z_OK)
            {
                if (req->code == SERVER_CMD_DOWNLOAD) //传输的是文件数据
                {
                    const char * remoteName = (char *)(req + 1);
                    const char * localName = remoteName + strlen(remoteName) + 1;
                    int ret = writeFile(localName, plain, plainLen);
                    if (ret < 0)
                    {
                        perror("\nwriteFile");
                    }
                    else
                    {
                        snprintf(msg, 255, "Download remote %s to %s success\n", remoteName, localName);
                    }
                }
                else
                {
                    plain[plainLen] = 0;
                    free(msg);
                    msg = (char *)malloc(plainLen + 10);
                    snprintf(msg, plainLen + 10, "\n%s\n", plain);
                }
            }
            else
            {
                snprintf(msg, 255, "uncompress %d, rsplen %d\n", ret, datalen);
            }
            free(plain);
        }
        else
        {
            if (req->code == SERVER_CMD_GETOUTERIP)
            {
                unsigned int * ip = (unsigned int *)(rsp->data);
                struct in_addr addr;
                addr.s_addr = ntohl(*ip);
                char * ipv4 = inet_ntoa(addr);
                char * hostname = (char *)(ip + 1);
                set_session_hostinfo(g_tls_myclientid, hostname, addr.s_addr);
                rsp->data[datalen] = 0;
                snprintf(msg, 255, "hostname:%s,ip:%s\n", hostname, ipv4);
            }
            else
            {
                rsp->data[datalen] = 0;
                free(msg);
                msg = (char *)malloc(datalen + 10);
                snprintf(msg, datalen + 10, "%s\n", rsp->data);
            }
        }
    }

    return msg;
}

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
        if (time(0) - g_alive_timestamp > g_conn_tmout_threshold)//超时没消息，退出线程
        {
            printf("\nsession[%d] timeout\n", g_tls_myclientid);
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

            struct CmdReq * req = (struct CmdReq *)dataReq;
            log_print("CLIENT[%d] cmd=%d come", g_tls_myclientid, req->code);
            if(req->code == INNER_CMD_QUERY_SESSION_TM)
            {
                char * buff = malloc(255);
                snprintf(buff, 255, "%d\n", g_conn_tmout_threshold);
                DataBuffer * data = (DataBuffer *)malloc(sizeof(DataBuffer));
                data->ptr = buff;
                data->len = strlen(data->ptr) + 1;
                if(write(cmdfd, &data, sizeof(data)) != sizeof(data))
                {
                    perror("parseCmdRsp write:");
                }
                continue;
            }
            else if(req->code == INNER_CMD_SET_SESSION_TM)
            {
                char * p_tm = req->data + strlen(req->data) + 1;
                int tm = atoi(p_tm);
                char * buff = malloc(255);
                if(tm <= 0)
                {
                    strcpy_s(buff, 255, "invalid tm value\n");
                }
                else
                {
                    g_conn_tmout_threshold = tm;
                    strcpy_s(buff, 255, "Success\n");
                }
                DataBuffer * data = (DataBuffer *)malloc(sizeof(DataBuffer));
                data->ptr = buff;
                data->len = strlen(data->ptr) + 1;
                if(write(cmdfd, &data, sizeof(data)) != sizeof(data))
                {
                    perror("parseCmdRsp write:");
                }
                continue;
            }
        }
        else if(hascmd == 0)
        {
            ((struct CmdReq *)dataReq)->code = 0;
            datalen = 8;
        }
        else
        {
            log_print("CLIENT[%d] conn_handler wait_data error!", g_tls_myclientid);
            continue;
        }
        
        unsigned char key[2];
        int ret = server_send_v2(datafd, dataReq, datalen, key);
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
            ret = server_recv_v2(datafd, dataRsp, sizeof(dataRsp), key);
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
