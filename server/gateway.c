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
#include "app.h"
#include <pthread.h>
#include <sys/socket.h>
#include <stdio.h>
#include "worker.h"

extern int s_currentSession;

void start_new_worker(unsigned short clientid);

int reply_ack_now(int fd, const struct FragmentCtrl * frag, char (*addr)[16])
{
    int ip = 0;
    char recvBuf[65536];
    struct CmdAckPayload * ack = (struct CmdAckPayload *)&ip;
    ack->seqid = frag->seqId;
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
            //debug("gateway: wait_data timeout.\n");
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
        
        struct FragmentCtrl * frag = (struct FragmentCtrl *)payload;
        const char fragEndFlag = frag->end;
        const unsigned short clientid = ntohs(frag->clientID);

        DataBuffer * data = (DataBuffer *)malloc(sizeof(DataBuffer));
        data->ptr = payload;
        data->len = pureLen; //FRAGMENT_CTRL + PAYLOAD
        int handler_fd = get_data_fd(clientid);
        if (handler_fd > 0)
        {
            //debug("gateway: enqueue msg clientid=%d, seqid=%d\n", clientid, frag->seqId);
            if(write(handler_fd, &data, sizeof(DataBuffer *)) != sizeof(DataBuffer *))
            {
                freeDataBuffer(data);
                perror("write handler fd");
                continue;
            }

            if (wait_data(handler_fd, 1) == 0)
            {
                debug("gateway: wait_data handle timeout.\n");
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
                debug("gateway: [[[ session establish sync for cliendid %d ]]].\n", clientid);
                if(reply_ack_now(fd, frag, addr) > 0)
                {
                    start_new_worker(clientid);
                }
            }
            else
            {
                debug("gateway: discard clientid %d, seqid=%d, code=%d\n", clientid, frag->seqId, req->code);
            }
            
            freeDataBuffer(data);
        }
    }
    return NULL;
}

void start_new_worker(unsigned short clientid)
{
    int sock_pair[2];
    int pipe_fds[2];
    if(socketpair(AF_LOCAL, SOCK_STREAM, 0, sock_pair) < 0) 
    { 
        perror("socketpair");
        return;
    }

    //printf("socketpair %d,%d\n", sock_pair[0], sock_pair[1]);
    if (pipe(pipe_fds) < 0)
    {
        perror("pipe");
        return;
    }
    
    /*
    创建2对FD，datafd用来gateway和conn_handler DNS包通信
    cmdfd用来命令行直接下发命令
    */
    struct WorkerArgs * args = (struct WorkerArgs *)malloc(sizeof(struct WorkerArgs));
    args->clientid = clientid;
    args->pipefd = pipe_fds[0];
    args->sockfd = sock_pair[0];

    pthread_t tid;
    if(pthread_create(&tid, NULL, conn_handler, (void *)args) != 0)
    {
        perror("pthread_create");
    }

    SessionEntry entry = {clientid, sock_pair[1], pipe_fds[1], 0, SYNC, {0}};
    add_session(clientid, &entry);

    if (s_currentSession >= 0)
    {
        printf("\nNew session %d connected\nSession[%d]>>", clientid, s_currentSession);
    }
}