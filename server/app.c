#include "app.h"
#include "../include/udp.h"
#include "../include/dns.h"
#include "../include/cmd.h"
#include "../include/util.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

extern __thread unsigned short g_tls_myclientid;

int isHello(const struct CmdReq * cmd)
{
    if(cmd->code != CLIENT_CMD_HELLO)
        return 0;
    //收到了hello，校验
    const struct Hello * hello = (const struct Hello *)cmd->data;
    unsigned short datalen = ntohs(cmd->datalen);
    if (datalen != sizeof(struct Hello))
    {
        return 0;
    }

    if(hello->msg[0] != 'H' || hello->msg[1] != 'A' || hello->msg[2] != 'L' || hello->msg[3] != 'O')
        return 0;

    if (ntohl(hello->timestamp) - time(0) >= 600)//hello有效期为10分钟
    {
        return 0;
    }
    
    //hello->key = ntohs(hello->key);//TODO 加密
    return 1;
}

/*
* 如果data为NULL，只回复ACK；否则ACK附加DATA一起回复
*/
static int server_reply_ack_with_data(int fd, const DataBuffer * serverData, const struct FragmentCtrl * frag)
{
    DataBuffer * rspData = 0;
    if (serverData)
    {
        int datalen = serverData->len + sizeof(struct CmdAckPayload);
        if (datalen < 64)
        {
            datalen = 64;
        }
                
        rspData = allocDataBuffer(datalen);
        memcpy_s(rspData->ptr + sizeof(struct CmdAckPayload), serverData->len, serverData->ptr, serverData->len);
    }
    else
    {
        rspData = allocDataBuffer(sizeof(struct CmdAckPayload));
    }
    
    struct CmdAckPayload * ack = (struct CmdAckPayload *)rspData->ptr;
    ack->seqid = frag->seqId;
    ack->ok[0] = 'O';
    ack->ok[1] = 'K';

    //printf("CLIENT[%d] send ack of seqid %d, clientid %d\n", g_tls_myclientid, frag->seqId, ntohs(frag->clientID));
    return write(fd, &rspData, sizeof(rspData));
}

/*
* server接收client的分片并完成组包
*/
int server_recv(int fd, char * buf, int len)
{
    char * recvBuf = buf;
    //维护一张表，用来记录当前序号的包是否已经收到
    char hashTable[32768] = {0};
    #define IS_FRAGMENT_ARRIVED(seqid) (hashTable[seqid] != 0)
    #define SET_FRAGMENT_ARRIVED(seqid) (hashTable[seqid] = 1)
    unsigned short lastSeqidAck = 0xffff;//客户端是顺序发送的
    time_t refreshTime = time(0);
    do
    {
        if (time(0) - refreshTime >= 10)//自从收到上一个数据包到现在超过10秒
        {
            break;
        }
        
        int ret = wait_data(fd, 10);
        if (ret == 0)
        {
            break;
        }
        else if (ret < 0)
        {
            return ret;
        }
        
        //有数据
        struct FragmentCtrl * frag = 0;
        DataBuffer * data = 0;
        if (read(fd, &data, sizeof(DataBuffer *)) != sizeof(DataBuffer *))
        {
            perror("conn_handler read");
            break;
        }

        frag = (struct FragmentCtrl *)(data->ptr);
        if (ntohs(frag->clientID) != g_tls_myclientid)
        {
            freeDataBuffer(data);
            continue;
        }
        
        struct CmdReq * cmd = (struct CmdReq *)(frag + 1);
        const int datalen = data->len - sizeof(*frag);
        //如果收到hello, 丢弃
        if(isHello(cmd))
        {
            if(server_reply_ack_with_data(fd, 0, frag) <= 0)
            {
                perror("server_reply_ack_with_data");
            }
            freeDataBuffer(data);
            continue;
        }

        time(&refreshTime);

        if(IS_FRAGMENT_ARRIVED(frag->seqId))
        {
            //printf("seqid %d duplicate.\n", frag.seqId);
            if(server_reply_ack_with_data(fd, 0, frag) <= 0)
            {
                perror("server_reply_ack_with_data");
                freeDataBuffer(data);
                return -1;
            }
        }
        else
        {
            const short expectedSeqId = GET_NEXT_SEQID(lastSeqidAck);
            //printf("CLIENT[%d] seqid = %d, expect = %d, end=%d\n", g_tls_myclientid, frag->seqId, expectedSeqId, frag->end);
            if(server_reply_ack_with_data(fd, 0, frag) <= 0)
            {
                perror("server_reply_ack_with_data");
                freeDataBuffer(data);
                return -1;
            }
            //报文是客户端顺序发送的，因此接收到最后一个包时要校验与上一个包是不是顺序下来的，防止上次会话的包重传产生错误
            if(frag->seqId == expectedSeqId || lastSeqidAck == 0xffff)
            {
                SET_FRAGMENT_ARRIVED(frag->seqId);
                //printf("%d:", pureLen);
                //dumpHex(recvBuf, pureLen);
                memcpy_s(recvBuf, len - (recvBuf - buf), cmd, datalen);
                recvBuf += datalen;
                lastSeqidAck = frag->seqId;
                if (frag->end)
                {
                    freeDataBuffer(data);
                    return recvBuf - buf;
                }
            }
            else
            {
                printf("drop seqid = %d\n", frag->seqId);
            }
            freeDataBuffer(data);
        }
    }while (1);

    printf("\nNetwork timeout\nSession[%d]>>", g_tls_myclientid);
    return 0;
}

/* 无法主动发送，必须等待client的心跳询问 */
int server_send(int fd, const char * p, int len)
{
    do
    {
        int ret = wait_data(fd, 5);
        if (ret == 0)
        {
            continue;
        }
        else if (ret < 0)
        {
            return ret;
        }

        struct FragmentCtrl * frag = 0;
        DataBuffer * data = 0;
        if (read(fd, &data, sizeof(DataBuffer *)) != sizeof(DataBuffer *))
        {
            perror("conn_handler read");
            break;
        }

        frag = (struct FragmentCtrl *)(data->ptr);
        if (ntohs(frag->clientID) != g_tls_myclientid)
        {
            freeDataBuffer(data);
            continue;
        }

        struct CmdReq * cmd = (struct CmdReq *)(frag + 1);
        if (!isHello(cmd))
        {
            goto ack;
        }
                
        freeDataBuffer(data);
        DataBuffer serverData = {p, len};
        return server_reply_ack_with_data(fd, &serverData, frag);
    ack:
        //ack分支是错误分支,不应该退出循环,应该继续重试
        server_reply_ack_with_data(fd, 0, frag);
        freeDataBuffer(data);
    }
    while(1);

    return 0;
}

