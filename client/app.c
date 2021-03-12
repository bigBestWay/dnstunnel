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

extern short g_seq_number;
extern unsigned short g_client_id;
long g_client_timestamp = 0;

void clientid_sequid_init()
{
    getRand(&g_seq_number, sizeof(g_seq_number));
    g_seq_number &= 0x7fff;
    getRand(&g_client_id, sizeof(g_client_id));
    debug("MYCLIENTID = %d\n", g_client_id);
}

/*
ack校验
返回值有3种：
0 不是ACK
1 是ACK并且序号正确
*/
static int check_ack(unsigned short seqId, const char * payload, int len)
{
    struct CmdAckPayload * ack = (struct CmdAckPayload *)payload;
    if (ack->ok[0] == 'O' && ack->ok[1] == 'K')
    {
        if(seqId == ack->seqid)
            return 1;
    }
    debug("check_ack false: seqid %d, ok[0]=%c, ok[1]=%c\n", ack->seqid, ack->ok[0], ack->ok[1]);
    return 0;
}

/*
* 可靠发送，成功返回len,超时返回1,错误返回-1
*/
static int client_send_reliable(int fd, unsigned short seqid, const char * packet, int len)
{
    char tmp[1024];
    char * buffer = tmp;
    int bufferLen = sizeof(tmp);
    int retry = 0, ret = 0;

    do
    {
        debug("client_send_reliable: write packet seqid=%d.\n", seqid);
        if(write(fd, packet, len) <= 0)
        {
            perror("write");
            return -1;
        }
    wait_label:
        ret = wait_data(fd, 5);//超时时限
        if(ret == 0)//超时重发
        {
            debug("client_send_reliable wait_data timeout.\n");
            ++ retry;
            if(retry > 5) //重试5次，超过结束
                break;
            continue;
        }
        else if (ret == -1)
        {
            perror("select");
            return -1;
        }
        
        int recvLen = read(fd, buffer, bufferLen);
        if (recvLen <= 0)
        {
            perror("read");
            return -1;
        }
        
        int payloadLen = 0;
        char * payload = parseResponse(buffer, recvLen, &payloadLen);
        if (payload && check_ack(seqid, payload, payloadLen) == 1)
        {
            debug("get ack of %d\n", seqid);
            //每次正确收到ACK都刷新时间戳
            time(&g_client_timestamp);
            return len;
        }
        
        goto wait_label;
    }while(1);

    debug("wait ack timeout %d\n", seqid);
    return -1;
}

/*
可靠发送，成功返回发送成功长度,超时返回0,错误返回-1
有一个分片没发成功，整个包都没发成功
*/
int client_send(int fd, const char * p, int len)
{
    int pkgNum = 0;
    struct QueryPkg * pkgs = buildQuerys(p, len, &pkgNum);
    int ret = 0;
    for (int i = 0; i < pkgNum; i++)
    {
        //dumpHex(pkgs[i].payload, pkgs[i].len);
        ret = client_send_reliable(fd, pkgs[i].seqId, pkgs[i].payload, pkgs[i].len); 
        free(pkgs[i].payload);
        pkgs[i].payload = 0;
        if (ret != pkgs[i].len)
        {
            return ret;
        }
    }
    free(pkgs);

    return len;
}

/* client的接收，实际是主动询问server并接收server命令 
返回值 接收到的数据长度
0，只接收到ack; > 0, 接收到payload; < 0 超时或错误
*/
int client_recv(int fd, char * p, int len)
{
    char packet[sizeof(struct CmdReq) + sizeof(struct Hello)];
    struct CmdReq * cmd = (struct CmdReq *)packet;
    cmd->code = SERVER_CMD_HELLo;
    cmd->datalen = htons(sizeof(struct Hello));
    struct Hello * hello = (struct Hello *)cmd->data;
    hello->msg[0] = 'H';
    hello->msg[1] = 'A';
    hello->msg[2] = 'L';
    hello->msg[3] = 'O';
    hello->timestamp = htonl(time(0));
    int ret = -1;

    int pkgNum = 0;
    struct QueryPkg * pkgs = buildQuerys(packet, sizeof(packet), &pkgNum);
    if (pkgNum == 1)
    {
        int retry = 0;
        do
        {
            ret = write(fd, pkgs[0].payload, pkgs[0].len);
            if (ret <= 0)
            {
                perror("write");
                break;
            }
        wait_label:
            ret = wait_data(fd, 2);
            if(ret < 0)
            {
                break;
            }
            else if (ret == 0)//超时重发
            {
                debug("client_recv: wait_data timeout.\n");
                ret = -1;//important
                ++ retry;
                if(retry > 5)
                    break;
                continue;
            }
                
            char buffer[65536];
            int recvLen = read(fd, buffer, sizeof(buffer));
            if (recvLen <= 0)
            {
                ret = -1;
                break;
            }
            
            int outlen = 0;
            char * payload = parseResponse(buffer, recvLen, &outlen);
            if (payload && check_ack(pkgs[0].seqId, payload, outlen) == 1)
            {
                if(outlen < sizeof(struct CmdAckPayload))
                {
                    ret = -1;
                    break;
                }

                debug("got hello ack %d!\n", pkgs[0].seqId);
                time(&g_client_timestamp);
                ret = outlen - sizeof(struct CmdAckPayload);
                if(outlen > sizeof(struct CmdAckPayload))
                {
                    memcpy_s(p, len, payload + sizeof(struct CmdAckPayload), outlen - sizeof(struct CmdAckPayload));
                }

                break;
            }

            goto wait_label;
        } while (1);
        free(pkgs[0].payload);
        pkgs[0].payload = 0;
    }
    else
    {
        for (int i = 0; i < pkgNum; i++)
        {
            free(pkgs[i].payload);
            pkgs[i].payload = 0;
        }
    }
    
    free(pkgs);
    return ret;
}