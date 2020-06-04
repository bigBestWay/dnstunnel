#include "app.h"
#include "udp.h"
#include "dns.h"
#include "cmd.h"
#include "util.h"
#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/*
* 如果data为NULL，只回复ACK；否则ACK附加DATA一起回复
*/
static int server_reply_ack_with_data(int fd, const DataBuffer * query, const DataBuffer * serverData, const struct FragmentCtrl * frag, char (*addr)[16])
{
    char buffer[65536];
    struct CmdAckPayload * ack = (struct CmdAckPayload *)buffer;
    ack->seqid = frag->seqId;
    ack->ok[0] = 'O';
    ack->ok[1] = 'K';

    int outlen = 0;
    char * out = 0;
    if (!frag->end)
    {
        out = buildResponseA(query->ptr, query->len, (unsigned int *)ack, &outlen);
    }
    else//最后一个分片是DNSKEY QUERY
    {
        int * a = (int *)ack;
        *a = htonl(*a);
        int sendlen = sizeof(*ack);
        if (serverData)
        {
            memcpy_s(ack + 1, sizeof(buffer) - sizeof(*ack), serverData->ptr, serverData->len);
            sendlen += serverData->len;
        }

        if (sendlen <= 4)//数据小于等于4容易有BUG，增加一些无所谓
        {
            sendlen += 8;
        }
        
        out = buildResponseDnskey(query->ptr, query->len, buffer, sendlen, &outlen);
    }
    
    if (out == 0)
    {
        printf("query packet len error %d.\n", query->len);
        return -1;
    }
    
    int ret = udp_send(fd, out, outlen, addr);
    free(out);
    return ret;
}

/*
* server接收client的分片并完成组包
*/
int server_recv(int fd, char * buf, int len, char (*addr)[16])
{
    char * recvBuf = buf;
    char querr_buffer[65536];
    //维护一张表，用来记录当前序号的包是否已经收到
    char hashTable[32768] = {0};
    #define IS_FRAGMENT_ARRIVED(seqid) (hashTable[seqid] != 0)
    #define SET_FRAGMENT_ARRIVED(seqid) (hashTable[seqid] = 1)
    unsigned short lastSeqidAck = 0;//客户端是顺序发送的
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
        int queryLen = udp_recv(fd, querr_buffer, sizeof(querr_buffer), addr);
        if(queryLen <= 0)
        {
            perror("udp_recv");
        }

        struct FragmentCtrl frag = {0, 0};
        int pureLen = processQuery(querr_buffer, queryLen, &frag, recvBuf, len - (recvBuf - buf));
        if (pureLen <= 0)//可能收到了一些其他报文，丢弃重试
        {
            continue;
        }

        //如果收到hello, 丢弃
        struct CmdReq * cmd = (struct CmdReq *)recvBuf;
        if(cmd->code == CLIENT_CMD_HELLO)
        {
            DataBuffer query = {querr_buffer, queryLen};
            if(server_reply_ack_with_data(fd, &query, 0, &frag, addr) <= 0)
            {
                perror("server_reply_ack_with_data");
            }
            continue;
        }

        time(&refreshTime);

        if(IS_FRAGMENT_ARRIVED(frag.seqId))
        {
            //printf("seqid %d duplicate.\n", frag.seqId);
            DataBuffer query = {querr_buffer, queryLen};
            if(server_reply_ack_with_data(fd, &query, 0, &frag, addr) <= 0)
                return ret;
        }
        else
        {
            //dumpHex(recvBuf, pureLen);                
            SET_FRAGMENT_ARRIVED(frag.seqId);

            printf("seqid = %d, end=%d\n", frag.seqId, frag.end);
            DataBuffer query = {querr_buffer, queryLen};
            if(server_reply_ack_with_data(fd, &query, 0, &frag, addr) <= 0)
                return ret;
            printf("sent ack of %d\n", frag.seqId);
            //报文是客户端顺序发送的，因此接收到最后一个包时要校验与上一个包是不是顺序下来的，防止上次会话的包重传产生错误
            if(frag.seqId == lastSeqidAck + 1 || lastSeqidAck == 0)
            {
                recvBuf += pureLen;
                lastSeqidAck = frag.seqId;
                if (frag.end)
                {
                    return recvBuf - buf;
                }
                
            }
        }
    }while (1);

    printf("server_recv timeout.\n");
    return 0;
}

/* 无法主动发送，必须等待client的心跳询问 */
int server_send(int fd, const char * p, int len, char (*addr)[16])
{
    char recvBuf[65536];
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

        int recvLen = udp_recv(fd, recvBuf, sizeof(recvBuf), addr);
        if (recvLen <= 0)
        {
            return recvLen;
        }
        
        struct FragmentCtrl frag = {0, 0};
        char payload[256];
        int pureLen = processQuery(recvBuf, recvLen, &frag, payload, sizeof(payload));
        if (pureLen <= 0)//可能收到了一些其他报文，丢弃重试
        {
            continue;
        }

        DataBuffer query = {recvBuf, recvLen};

        struct CmdReq * cmd = (struct CmdReq *)payload;
        if(cmd->code != CLIENT_CMD_HELLO)
            goto ack;
        //收到了hello，校验
        struct Hello * hello = (struct Hello *)cmd->data;
        cmd->datalen = ntohs(cmd->datalen);
        if (cmd->datalen != sizeof(struct Hello))
        {
            goto ack;
        }
        hello->key = ntohs(hello->key);//TODO 加密
        if(hello->msg[0] != 'H' || hello->msg[1] != 'A' || hello->msg[2] != 'L' || hello->msg[3] != 'O')
            goto ack;

        DataBuffer serverData = {p, len};
        return server_reply_ack_with_data(fd, &query, &serverData, &frag, addr);
    ack:
        return server_reply_ack_with_data(fd, &query, 0, &frag, addr);
    }
    while(1);

    return 0;
}

