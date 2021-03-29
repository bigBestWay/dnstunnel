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
#include "log.h"

extern __thread unsigned short g_tls_myclientid;
extern __thread time_t g_alive_timestamp;
extern __thread time_t g_conn_tmout_threshold;

int isHello(struct CmdReq * cmd)
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

    unsigned char key[2] = {cmd->data[0], cmd->data[1]};
    xor(cmd->data + 2, datalen - 2, key);

    if(hello->msg[0] != 'H' || hello->msg[1] != 'A' || hello->msg[2] != 'L' || hello->msg[3] != 'O')
        return 0;

    if (ntohl(hello->timestamp) - time(0) >= 60)//hello有效期为1分钟
    {
        log_print("Hello expired.");
        return 0;
    }

    return 1;
}

int is_session_establish_sync(struct CmdReq * cmd)
{
    if(cmd->code != SERVER_CMD_NEWSESSION_SYNC)
        return 0;

    const struct NewSession * data = (const struct NewSession *)cmd->data;
    unsigned short datalen = ntohs(cmd->datalen);
    if (datalen != sizeof(struct NewSession))
    {
        return 0;
    }

    unsigned char key[2] = {cmd->data[0], cmd->data[1]};
    xor(cmd->data + 2, datalen - 2, key);

    if(data->magic[0] != '\xde' || data->magic[1] != '\xad' || data->magic[2] != '\xca' || data->magic[3] != '\xfe')
        return 0;

    if (ntohl(data->timestamp) - time(0) >= 60)//有效期为1分钟
    {
        log_print("is_session_establish_sync expired.");
        return 0;
    }

    return 1;
}

/*
* 如果data为NULL，只回复ACK；否则ACK附加DATA一起回复
*/
static int server_reply_ack_with_data_v2(int fd, const DataBuffer * serverData, const struct FragmentCtrlv2 * frag, unsigned char * key)
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
        getRand(rspData->ptr, rspData->len);
        memcpy_s(rspData->ptr + sizeof(struct CmdAckPayload), serverData->len, serverData->ptr, serverData->len);
    }
    else
    {
        rspData = allocDataBuffer(sizeof(struct CmdAckPayload));
    }
    
    struct CmdAckPayload * ack = (struct CmdAckPayload *)rspData->ptr;
    ack->seqid = htons(frag->seqId);
    ack->ok[0] = 'O';
    ack->ok[1] = 'K';

    xor(rspData->ptr, rspData->len, key);
    log_print("CLIENT[%d] send ack of seqid %d, clientid %d", g_tls_myclientid, frag->seqId, frag->clientID);
    return write(fd, &rspData, sizeof(rspData));
}

/*
* server接收client的分片并完成组包
*/
int server_recv_v2(int fd, char * buf, int len, unsigned char * key)
{
    char * recvBuf = buf;
    //维护一张表，用来记录当前序号的包是否已经收到
    DataBuffer * recvTable[16384] = {0};
    #define IS_FRAGMENT_ARRIVED_V2(seqid) (recvTable[seqid] != 0)
    #define SET_FRAGMENT_ARRIVED_V2(seqid, data) (recvTable[seqid] = data)
    #define GET_FRAGMENT_DATA_V2(seqid) recvTable[seqid]
    int ret = 0;
    //log_print("CLIENT[%d] server_recv: enter.\n", g_tls_myclientid);
    short begin_seqid = -1, end_seqid = -1;
    do
    {
        if (time(0) - g_alive_timestamp >= g_conn_tmout_threshold)//统一为30s
        {
            log_print("CLIENT[%d] server_recv: refreshTime timeout", g_tls_myclientid);
            break;
        }
        
        ret = wait_data(fd, 10);
        if (ret == 0)
        {
            log_print("CLIENT[%d] server_recv: wait_data timeout", g_tls_myclientid);
            continue;
        }
        else if (ret < 0)
        {
            goto exit_lable;
        }
        
        //有数据
        struct FragmentCtrlv2 * frag = 0;
        DataBuffer * data = 0;
        if (read(fd, &data, sizeof(DataBuffer *)) != sizeof(DataBuffer *))
        {
            perror("conn_handler read");
            break;
        }
        
        frag = (struct FragmentCtrlv2 *)(data->ptr);
        if (frag->clientID != g_tls_myclientid)
        {
            freeDataBuffer(data);
            continue;
        }
        
        {
            struct CmdReq * cmd = (struct CmdReq *)(frag + 1);
            //如果收到hello, 丢弃
            if(isHello(cmd) || is_session_establish_sync(cmd))
            {
                unsigned char key[2] = {cmd->data[0], cmd->data[1]};
                if(server_reply_ack_with_data_v2(fd, 0, frag, key) <= 0)
                {
                    perror("server_reply_ack_with_data_v2");
                }
                freeDataBuffer(data);
                continue;
            }
        }

        time(&g_alive_timestamp);

        if(IS_FRAGMENT_ARRIVED_V2(frag->seqId))
        {
            log_print("seqid %d duplicate.", frag->seqId);
            if(server_reply_ack_with_data_v2(fd, 0, frag, key) <= 0)
            {
                perror("server_reply_ack_with_data_v2");
                freeDataBuffer(data);
                ret = -1;
                goto exit_lable;
            }
        }
        else
        {
            if (frag->begin)
            {
                if(begin_seqid > 0)
                {
                    log_print("server_recv_v2: error,another begin packet!\n");
                    ret = -1;
                    goto exit_lable;
                }
                begin_seqid = frag->seqId;
                log_print("server_recv_v2: begin seqid = %d", begin_seqid);
            }
            
            if(frag->end)
            {
                if(end_seqid > 0)
                {
                    log_print("server_recv_v2: error,another end packet!\n");
                    ret = -1;
                    goto exit_lable;
                }
                end_seqid = frag->seqId;
                log_print("server_recv_v2: end seqid = %d", end_seqid);
            }

            //log_print("CLIENT[%d] seqid = %d, expect = %d, end=%d\n", g_tls_myclientid, frag->seqId, expectedSeqId, frag->end);
            if(server_reply_ack_with_data_v2(fd, 0, frag, key) <= 0)
            {
                perror("server_reply_ack_with_data_v2");
                freeDataBuffer(data);
                ret = -1;
                goto exit_lable;
            }

            log_print("server_recv_v2: data arrvied seqid=%d", frag->seqId);
            SET_FRAGMENT_ARRIVED_V2(frag->seqId, data);

            //连续性检查
            if(begin_seqid > 0 && end_seqid > 0)
            {
                if(begin_seqid == end_seqid)//只有一个包
                {
                    const int datalen = data->len - sizeof(*frag);
                    memcpy_s(recvBuf, len - (recvBuf - buf), data->ptr + sizeof(struct FragmentCtrlv2), datalen);
                    recvBuf += datalen;
                    freeDataBuffer(data);
                    ret = recvBuf - buf;
                    xor(buf, ret, key);
                    goto exit_lable;
                }

                int isAllOk = 1;
                for(short i = begin_seqid; i != GET_NEXT_SEQID_V2(end_seqid); i = GET_NEXT_SEQID_V2(i))
                {
                    if(!IS_FRAGMENT_ARRIVED_V2(i))
                    {
                        log_print("server_recv_v2: seqid %d not arrvied.", i);
                        isAllOk = 0;
                        break;
                    }
                }
                
                if (isAllOk)
                {
                    log_print("server_recv_v2: combine packet!");
                    for(short i = begin_seqid; i != GET_NEXT_SEQID_V2(end_seqid); i = GET_NEXT_SEQID_V2(i))
                    {
                        DataBuffer * d = GET_FRAGMENT_DATA_V2(i);
                        const int datalen = d->len - sizeof(*frag);
                        memcpy_s(recvBuf, len - (recvBuf - buf), d->ptr + sizeof(struct FragmentCtrlv2), datalen);
                        recvBuf += datalen;
                        freeDataBuffer(d);
                    }

                    ret = recvBuf - buf;
                    xor(buf, ret, key);
                    goto exit_lable;
                }
            }
        }
    }while (1);

    ret = 0;
exit_lable:
    //log_print("CLIENT[%d] server_recv: exit.", g_tls_myclientid);
    return ret;
}

/* 无法主动发送，必须等待client的心跳询问 
注意: datafd 上传输的都是指针，内存必须要重新申请
*/
int server_send_v2(int fd, const char * p, int len, unsigned char * key)
{
    int retry = 0;
    do
    {
        int ret = wait_data(fd, 5);
        if (ret == 0)
        {
            log_print("CLIENT[%d] server_send wait_data timeout", g_tls_myclientid);
            ++ retry;
            continue;
        }
        else if (ret < 0)
        {
            return ret;
        }

        struct FragmentCtrlv2 * frag = 0;
        DataBuffer * data = 0;
        if (read(fd, &data, sizeof(DataBuffer *)) != sizeof(DataBuffer *))
        {
            perror("conn_handler read");
            break;
        }

        frag = (struct FragmentCtrlv2 *)(data->ptr);
        if (frag->clientID != g_tls_myclientid)
        {
            log_print("frage->clientid[%d] != g_tls_myclientid[%d]", frag->clientID, g_tls_myclientid);
            freeDataBuffer(data);
            continue;
        }

        struct CmdReq * cmd = (struct CmdReq *)(frag + 1);
        key[0] = cmd->data[0];
        key[1] = cmd->data[1];

        int is_hello = isHello(cmd);
        if (!is_hello && !is_session_establish_sync(cmd))
        {
            log_print("server_send: not a hello or session-established msg, code=%d, seqid=%d", cmd->code, frag->seqId);
            goto ack;
        }

        if(is_hello && get_session_state(g_tls_myclientid) == SYNC)
        {
            log_print("CLIENT[%d] set_session_state BUSY.", g_tls_myclientid);
            set_session_state(g_tls_myclientid, BUSY);
        }

        DataBuffer serverData = {(char *)p, len};
        ret = server_reply_ack_with_data_v2(fd, &serverData, frag, key);
        
        freeDataBuffer(data);
        return ret;
    ack:
        //emptyRsp分支是错误分支,不应该退出循环,应该继续重试
        server_reply_ack_with_data_v2(fd, 0, frag, key);
        freeDataBuffer(data);
    }
    while(retry < 5);

    return 0;
}
