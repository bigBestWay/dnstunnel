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
extern short g_client_id;

void client_app_init()
{
    getRand(&g_seq_number, sizeof(g_seq_number));
    g_seq_number &= 0x7fff;
    getRand(&g_client_id, sizeof(g_client_id));
}

static int check_ack(unsigned short seqId, const char * payload, int len)
{
    struct CmdAckPayload * ack = (struct CmdAckPayload *)payload;
    //swap一下
    int * a = (int *)payload;
    *a = ntohl(*a);

    if (ack->ok[0] == 'O' && ack->ok[1] == 'K' && seqId == ack->seqid)
    {
        return 1;
    }
    return 0;
}

/*
* 可靠发送，成功返回0
*/
static int client_send_reliable(int fd, unsigned short seqid, const char * packet, int len)
{
    char tmp[1024];
    char * buffer = tmp;
    int bufferLen = sizeof(tmp);
    int retry = 0;
    do
    {
        if(write(fd, packet, len) <= 0)
        {
            perror("write");
            return -1;
        }

        int ret = wait_data(fd, 5);//超时时限
        if(ret == 0)//超时重发
        {
            ++ retry;
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
            printf("get ack of %d\n", seqid);
            return 0;
        }
    }while(retry < 5);
    return -1;
}

int client_send(int fd, const char * p, int len)
{
    int pkgNum = 0;
    struct QueryPkg * pkgs = buildQuerys(p, len, &pkgNum);
    for (int i = 0; i < pkgNum; i++)
    {
        printf("seqid = %d\n", pkgs[i].seqId);
        //dumpHex(pkgs[i].payload, pkgs[i].len);
        int ret = write(fd, pkgs[i].payload, pkgs[i].len);
        if (ret <= 0)
        {
            perror("write");
        }

        ret = client_send_reliable(fd, pkgs[i].seqId, pkgs[i].payload, pkgs[i].len);
        if (ret != 0)
        {
            return ret;
        }
                
        free(pkgs[i].payload);
        pkgs[i].payload = 0;
    }
    free(pkgs);

    return len;
}

/* client的接收，实际是主动询问server并接收server命令 */
int client_recv(int fd, char * p, int len)
{
    char packet[sizeof(struct CmdReq) + sizeof(struct Hello)];
    struct CmdReq * cmd = (struct CmdReq *)packet;
    cmd->code = CLIENT_CMD_HELLO;
    cmd->datalen = htons(sizeof(struct Hello));
    struct Hello * hello = (struct Hello *)cmd->data;
    hello->msg[0] = 'H';
    hello->msg[1] = 'A';
    hello->msg[2] = 'L';
    hello->msg[3] = 'O';
    getRand(&hello->key, sizeof(hello->key));
    hello->key = htons(hello->key);
    hello->clientID = htons(g_client_id);
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
        
            ret = wait_data(fd, 5);
            if(ret < 0)
            {
                break;
            }
            else if (ret == 0)//超时重发
            {
                ++ retry;
                continue;
            }
                
            char buffer[65536];
            int recvLen = read(fd, buffer, sizeof(buffer));
            if (recvLen <= 0)
            {
                break;
            }
                    
            int outlen = 0;
            char * payload = parseResponse(buffer, recvLen, &outlen);
            if (payload && check_ack(pkgs[0].seqId, payload, outlen))
            {
                printf("got hello ack %d!\n", pkgs[0].seqId);
                if (outlen > sizeof(struct CmdAckPayload))
                {
                    memcpy_s(p, len, payload + sizeof(struct CmdAckPayload), outlen - sizeof(struct CmdAckPayload));
                }
                ret = outlen - sizeof(struct CmdAckPayload);
                break;
            }
        } while (retry < 5);
        free(pkgs[0].payload);
        pkgs[0].payload = 0;
    }

    free(pkgs);
    return ret;
}