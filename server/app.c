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
#include "session.h"

extern __thread unsigned short g_tls_myclientid;

int isHello(const struct CmdReq * cmd)
{
    if(cmd->code != SERVER_CMD_HELLo)
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

    if (ntohl(hello->timestamp) - time(0) >= 60)//hello有效期为1分钟
    {
        debug("Hello expired.\n");
        return 0;
    }

    return 1;
}

int is_session_establish_sync(const struct CmdReq * cmd)
{
    if(cmd->code != SERVER_CMD_NEWSESSION_SYNC)
        return 0;

    const struct NewSession * data = (const struct NewSession *)cmd->data;
    unsigned short datalen = ntohs(cmd->datalen);
    if (datalen != sizeof(struct NewSession))
    {
        return 0;
    }

    if(data->magic[0] != '\xde' || data->magic[1] != '\xad' || data->magic[2] != '\xca' || data->magic[3] != '\xfe')
        return 0;

    if (ntohl(data->timestamp) - time(0) >= 60)//有效期为1分钟
    {
        debug("is_session_establish_sync expired.\n");
        return 0;
    }

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

    debug("CLIENT[%d] send ack of seqid %d, clientid %d\n", g_tls_myclientid, frag->seqId, ntohs(frag->clientID));
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
    int ret = 0;
    //debug("CLIENT[%d] server_recv: enter.\n", g_tls_myclientid);
    do
    {
        if (time(0) - refreshTime >= 300)//自从收到上一个数据包到现在超过5分钟
        {
            debug("CLIENT[%d] server_recv: refreshTime timeout\n", g_tls_myclientid);
            break;
        }
        
        ret = wait_data(fd, 10);
        if (ret == 0)
        {
            debug("CLIENT[%d] server_recv: wait_data timeout\n", g_tls_myclientid);
            continue;
        }
        else if (ret < 0)
        {
            goto exit_lable;
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
        if(isHello(cmd) || is_session_establish_sync(cmd))
        {
            if(server_reply_ack_with_data(fd, 0, frag) <= 0)
            {
                perror("server_reply_null_data");
            }
            freeDataBuffer(data);
            continue;
        }

        time(&refreshTime);

        if(IS_FRAGMENT_ARRIVED(frag->seqId))
        {
            debug("seqid %d duplicate.\n", frag->seqId);
            if(server_reply_ack_with_data(fd, 0, frag) <= 0)
            {
                perror("server_reply_ack_with_data");
                freeDataBuffer(data);
                ret = -1;
                goto exit_lable;
            }
        }
        else
        {
            const short expectedSeqId = GET_NEXT_SEQID(lastSeqidAck);
            //debug("CLIENT[%d] seqid = %d, expect = %d, end=%d\n", g_tls_myclientid, frag->seqId, expectedSeqId, frag->end);
            if(server_reply_ack_with_data(fd, 0, frag) <= 0)
            {
                perror("server_reply_ack_with_data");
                freeDataBuffer(data);
                ret = -1;
                goto exit_lable;
            }
            //报文是客户端顺序发送的，因此接收到最后一个包时要校验与上一个包是不是顺序下来的，防止上次会话的包重传产生错误
            if(frag->seqId == expectedSeqId || lastSeqidAck == 0xffff)
            {
                SET_FRAGMENT_ARRIVED(frag->seqId);
                //dumpHex(recvBuf, pureLen);
                memcpy_s(recvBuf, len - (recvBuf - buf), cmd, datalen);
                recvBuf += datalen;
                lastSeqidAck = frag->seqId;
                if (frag->end)
                {
                    freeDataBuffer(data);
                    ret = recvBuf - buf;
                    goto exit_lable;
                }
            }
            else
            {
                debug("drop seqid = %d\n", frag->seqId);
            }
            freeDataBuffer(data);
        }
    }while (1);

    ret = 0;
    printf("\nNetwork timeout\nSession[%d]>>", g_tls_myclientid);
exit_lable:
    //debug("CLIENT[%d] server_recv: exit.\n", g_tls_myclientid);
    return ret;
}

/* 无法主动发送，必须等待client的心跳询问 
注意: datafd 上传输的都是指针，内存必须要重新申请
*/
int server_send(int fd, const char * p, int len)
{
    int retry = 0;
    do
    {
        int ret = wait_data(fd, 5);
        if (ret == 0)
        {
            debug("CLIENT[%d] server_send wait_data timeout\n", g_tls_myclientid);
            ++ retry;
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
            debug("frage->clientid[%d] != g_tls_myclientid[%d]\n", ntohs(frag->clientID), g_tls_myclientid);
            freeDataBuffer(data);
            continue;
        }

        const struct CmdReq * cmd = (struct CmdReq *)(frag + 1);
        int is_hello = isHello(cmd);
        if (!is_hello && !is_session_establish_sync(cmd))
        {
            debug("server_send: not a hello or session-established msg, code=%d, seqid=%d\n", cmd->code, frag->seqId);
            goto ack;
        }

        if(is_hello && get_session_state(g_tls_myclientid) == SYNC)
        {
            debug("CLIENT[%d] set_session_state BUSY.\n", g_tls_myclientid);
            set_session_state(g_tls_myclientid, BUSY);
        }

        DataBuffer serverData = {p, len};
        ret = server_reply_ack_with_data(fd, &serverData, frag);
        
        freeDataBuffer(data);
        return ret;
    ack:
        //emptyRsp分支是错误分支,不应该退出循环,应该继续重试
        server_reply_ack_with_data(fd, 0, frag);
        freeDataBuffer(data);
    }
    while(retry < 5);

    return 0;
}

