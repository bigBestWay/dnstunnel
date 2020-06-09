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

unsigned short g_client_id = 0;

static int s_dnskey_min_rsp = 64; //最大437

static int isHello(const char * payload)
{
    const struct CmdReq * cmd = (const struct CmdReq *)payload;
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
    //hello->key = ntohs(hello->key);//TODO 加密
    return 1;
}

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

        if (sendlen < s_dnskey_min_rsp)//数据小于等于64容易有BUG，增加一些无所谓
        {
            sendlen = s_dnskey_min_rsp;
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
    //printf("sent ack of %d\n", frag->seqId);
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
        if(isHello(recvBuf))
        {
            DataBuffer query = {querr_buffer, queryLen};
            if(server_reply_ack_with_data(fd, &query, 0, &frag, addr) <= 0)
            {
                perror("server_reply_ack_with_data");
            }
            continue;
        }

        //校验clientid
        if (g_client_id == 0)
        {
            printf("WTF?\n");
        }
        else
        {
            if (g_client_id != ntohs(frag.clientID))
            {
                printf("clientid %d already died, seqid %d\n", ntohs(frag.clientID), frag.seqId);
                continue;
            }
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
            const short expectedSeqId = GET_NEXT_SEQID(lastSeqidAck);
            //printf("seqid = %d, expect = %d, end=%d\n", frag.seqId, expectedSeqId, frag.end);
            DataBuffer query = {querr_buffer, queryLen};
            if(server_reply_ack_with_data(fd, &query, 0, &frag, addr) <= 0)
                return ret;
            //报文是客户端顺序发送的，因此接收到最后一个包时要校验与上一个包是不是顺序下来的，防止上次会话的包重传产生错误
            if(frag.seqId == expectedSeqId || lastSeqidAck == 0xffff)
            {
                SET_FRAGMENT_ARRIVED(frag.seqId);
                //printf("%d:", pureLen);
                //dumpHex(recvBuf, pureLen);
                recvBuf += pureLen;
                lastSeqidAck = frag.seqId;
                if (frag.end)
                {
                    return recvBuf - buf;
                }
            }
            else
            {
                printf("drop seqid = %d\n", frag.seqId);
            }
        }
    }while (1);

    printf("Network timeout\n>>");
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
        if (!isHello(payload))
        {
            goto ack;
        }
        
        struct Hello * hello = (struct Hello *)cmd->data;
        //hello数据携带有clientid
        unsigned short clientid = ntohs(hello->clientID);
        if (ntohs(frag.clientID) != clientid)
        {
            printf("bad hello seqid = %d\n", frag.seqId);
            continue;
        }
        
        if (g_client_id == 0)
        {
            g_client_id = clientid;
        }
        else
        {
            if (g_client_id != clientid)
            {
                printf("clientid %d already died, now %d\n", clientid, g_client_id);
                goto ack;
            }
        }
        
        DataBuffer serverData = {p, len};
        return server_reply_ack_with_data(fd, &query, &serverData, &frag, addr);
    ack:
        //ack分支是错误分支,不应该退出循环,应该继续重试
        server_reply_ack_with_data(fd, &query, 0, &frag, addr);
    }
    while(1);

    return 0;
}

