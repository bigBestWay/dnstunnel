/*
* 根据clientid进行线程派发
*/
#include "../include/util.h"
#include "udp.h"
#include "dns.h"
#include "session.h"
#include "../include/cmd.h"
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "app.h"
#include <pthread.h>
#include <sys/socket.h>
#include <stdio.h>
#include "worker.h"
#include "log.h"

void start_new_worker(unsigned short clientid);

static int reply_ack_now(int fd, short seqid, char (*addr)[16])
{
    unsigned int ip = 0;
    char recvBuf[65536];
    struct CmdAckPayload * ack = (struct CmdAckPayload *)&ip;
    ack->seqid = seqid;
    ack->ok[0] = 'O';
    ack->ok[1] = 'K';

    char * out = 0;
    int outlen = 0;
    out = buildResponseA(recvBuf, sizeof(recvBuf), &ip, &outlen);
    return udp_send(fd, out, outlen, addr);
}

void * gateway(void * arg)
{
    int fd = udp_bind(53);
    if (fd == -1)
    {
        exit(1);
    }

    char recvBuf[65536];
    while(1)
    {
        int hasData = wait_data(fd, 5);
        if(hasData == 0)
        {
            //log_print("gateway: wait_data timeout.");
            continue;
        }
        else if (hasData < 0)
        {
            perror("wait_data");
            break;
        }

        char addr[1][16];
        int recvLen = udp_recv(fd, recvBuf, sizeof(recvBuf), addr);
        if (recvLen <= 0)
        {
            return NULL;
        }
        
        #define BUFFLEN 260
        char * payload = (char *)malloc(BUFFLEN);
        int pureLen = processQuery(recvBuf, recvLen, payload, BUFFLEN);
        if (pureLen <= 0)//可能收到了一些其他报文，丢弃重试
        {
            free(payload);
            continue;
        }
        
        //V2兼容
        struct FragmentCtrlv2 * frag = (struct FragmentCtrlv2 *)payload;
        const char fragEndFlag = frag->end;
        const unsigned short clientid = ntohs(frag->clientID);

        DataBuffer * data = (DataBuffer *)malloc(sizeof(DataBuffer));
        data->ptr = payload;
        data->len = pureLen; //FRAGMENT_CTRL + PAYLOAD
        int handler_fd = get_data_fd(clientid);
        if (handler_fd > 0)
        {
            //log_print("gateway: enqueue msg clientid=%d, seqid=%d", clientid, frag->seqId);
            if(write(handler_fd, &data, sizeof(DataBuffer *)) != sizeof(DataBuffer *))
            {
                freeDataBuffer(data);
                perror("write handler fd");
                continue;
            }

            if (wait_data(handler_fd, 1) == 0)
            {
                log_print("gateway: wait_data handle timeout.");
                continue;
            }
            
            DataBuffer * databack = 0;
            if (read(handler_fd, &databack, sizeof(DataBuffer *)) != sizeof(DataBuffer *))
            {
                perror("read handler fd");
                continue;
            }

            {
                const char * rspData = databack->ptr;
                const int rspDataLen = databack->len;
                char * out = 0;
                int outlen = 0;
                if (!fragEndFlag)
                {
                    out = buildResponseA(recvBuf, recvLen, (unsigned int *)rspData, &outlen);
                }
                else//最后一个分片是DNSKEY QUERY
                {                    
                    out = buildResponseDnskey(recvBuf, recvLen, rspData, rspDataLen, &outlen);
                }

                if(udp_send(fd, out, outlen, addr) <= 0)
                {
                    perror("gateway udp_send:");
                }
            }

            freeDataBuffer(databack);
        }
        else 
        {
            //新启动线程，接收到SERVER_CMD_NEWSESSION时
            const struct CmdReq * req = (struct CmdReq *)(frag + 1);
            if (is_session_establish_sync(req))
            {
                log_print("gateway: [[[ session establish sync for cliendid %d ]]].", clientid);
                if(reply_ack_now(fd, frag->seqId, addr) > 0)
                {
                    start_new_worker(clientid);
                }
            }
            else
            {
                log_print("gateway: discard clientid %d, seqid=%d, code=%d", clientid, frag->seqId, req->code);
            }
            
            freeDataBuffer(data);
        }
    }
    return NULL;
}

void start_new_worker(unsigned short clientid)
{
    int datafds[2];
    int cmdfds[2];
    if(socketpair(AF_LOCAL, SOCK_STREAM, 0, datafds) < 0) 
    { 
        perror("socketpair");
        return;
    }

    //printf("socketpair %d,%d\n", sock_pair[0], sock_pair[1]);
    if(socketpair(AF_LOCAL, SOCK_STREAM, 0, cmdfds) < 0) 
    {
        perror("socketpair");
        return;
    }
    
    /*
    创建2对FD，datafd用来gateway和conn_handler DNS包通信
    cmdfd用来命令行直接下发命令
    */
    struct WorkerArgs * args = (struct WorkerArgs *)malloc(sizeof(struct WorkerArgs));
    args->clientid = clientid;
    args->cmdfd = cmdfds[0];
    args->datafd = datafds[0];

    pthread_t tid;
    if(pthread_create(&tid, NULL, conn_handler, (void *)args) != 0)
    {
        perror("pthread_create");
    }

    SessionEntry entry = {clientid, datafds[1], cmdfds[1], 0, SYNC, {0}};
    add_session(clientid, &entry);
}