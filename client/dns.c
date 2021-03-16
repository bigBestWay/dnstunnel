#include "../include/dns.h"
#include "../include/base32.h"
#include "../include/util.h"
#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
/* 设计思想：为了更方便隐藏流量，不被发现，采用更隐秘的Resource Record
https://www.cloudshark.org/captures/79e23786259b
client -> server: query A, accept DNSSEC security RRs
server -> client: answer with RRSIG RR，signature 可用来传输数据
另一种：
client -> server: query DNSKEY, accept DNSSEC security RRs
server -> client: answer DNSKEY, publickey 可用来传输数据
 */

char g_baseDomain[255] = {0};
short g_seq_number = 0;
unsigned short g_client_id = 0;

static short getNewSeqId_v2()
{
    if(g_seq_number == 0x3fff)
        g_seq_number = 0;
    return g_seq_number++;
}
/*
**从www.baidu.com转换到3www5baidu3com
**返回值 格式后字符串长度，不包含0
*/
static int formatDomainName(const char* in, char* out) 
{
    char count = 0;
    int num_offset = 0;
    for(int i = 0; in[i] != 0; ++i)
    {
        if (in[i] == '.')
        {
            out[num_offset] = count;
            num_offset += count + 1;
            count = 0;
        }
        else
        {
            out[num_offset + 1 + count] = in[i];
            ++ count;
        }
    }
    out[num_offset] = count;
    return num_offset + count + 1;
}

/*
* client使用
* 如果使用域名上那几个字母传递数据，最大只能是255，效率非常低。
* ---[FAIL，转发时并不会附带此OPTION] 暂时决定使用EDNS[0] OPT RR中OPTION-PADDING TLV来传输数据。
* ---[FAIL, 一个DNS查询里只能有一个question]
* 数据加密后base32，作为hostname
* Each label can be up to 63 bytes long. The total length of a domain name cannot exceed 255 bytes, including the dots.
*/
static char * buildQuery_V2(const char * payload, int len, int isFirst, int isLast, unsigned short * seqIdOut, int * outlen)
{
    /*
    DNS头:question n, addtional RR 1
    Query RR
        Domain Name
        QUESTION
    Addtional RR
    */
    int mallocLen = sizeof(struct DNS_HEADER);
    mallocLen += MAX_DOMAINNAME_BYTES + sizeof(struct QUESTION);
    mallocLen += sizeof(struct EDNS0_OPT_RR);
    //mallocLen += sizeof(struct EDNS0_OPT_RR_OPTION);
    //mallocLen += len;

    /* 按domainName最大进行malloc */
    char * out = (char *)malloc(mallocLen);

    struct DNS_HEADER * dns_head = (struct DNS_HEADER *)out;
    /*设置DNS报文首部*/
    unsigned short sid = 0;
    getRand(&sid, sizeof(sid));
    dns_head->id = htons(sid);//id随机
    dns_head->qr = 0; //查询
    dns_head->opcode = 0; //标准查询
    dns_head->aa = 0; //不授权回答
    dns_head->tc = 0; //不可截断
    dns_head->rd = 1; //期望递归
    dns_head->ra = 0; //不可用递归
    dns_head->z = 0; //必须为0
    dns_head->ad = 0;
    dns_head->cd = 0;
    dns_head->rcode = 0;//没有差错
    dns_head->q_count = htons(1); //1个问题
    dns_head->ans_count = 0; 
    dns_head->auth_count = 0;
    dns_head->add_count = htons(1); //1个addtional RR

    char * position = out + sizeof(struct DNS_HEADER);

    //会话及分片信息，是否最后一片
    struct FragmentCtrlv2 fregHead;
    short seqId = getNewSeqId_v2();
    *seqIdOut = seqId;
    fregHead.seqId = seqId;
    fregHead.begin = isFirst == 1;
    fregHead.end = isLast == 1;
    fregHead.clientID = htons(g_client_id);

    char fragmentData[255];
    memcpy_s(fragmentData, sizeof(fragmentData), &fregHead, sizeof(fregHead));
    memcpy_s(fragmentData + sizeof(fregHead), sizeof(fragmentData)-sizeof(fregHead), payload, len);

    int payloadlen = len + sizeof(fregHead);
    char tmp[255] = {0};
    //dumpHex(fragmentData, payloadlen);
    base32_encode((const uint8_t *)fragmentData, payloadlen, (uint8_t *)tmp, sizeof(tmp));
    //debug("after base32[%d]: %s\n", strlen(tmp), tmp);
    strcat(tmp, g_baseDomain);
    /*设置query hostName*/
    int nameLen = formatDomainName(tmp, position);
    position[nameLen] = 0;
    position += nameLen + 1;//还有一个\0
    /*设置QUERY为A类型*/
    struct QUESTION * question = (struct QUESTION *)position;
    question->qclass = htons(1);//HOST IN
    if(!isLast)
    {
        question->qtype = htons(QUERY_A);//A
    }
    else
    {
        question->qtype = htons(QUERY_DNSKEY);
    }
    
    position += sizeof(struct QUESTION);

    /*设置addtional RR*/
    struct EDNS0_OPT_RR * opt = (struct EDNS0_OPT_RR *)position;
    opt->name[0] = 0;
    opt->type = htons(41);//OPT type
    opt->udp_size = htons(4096);
    opt->extendRTcode = 0;
    opt->ednsVersion = 0;
    opt->z_flag = htons(0x8000);
    opt->data_len = 0;
    position += sizeof(struct EDNS0_OPT_RR);
    
    *outlen = position - out;
    
    return out;
}

/*
* client使用
* Each label can be up to 63 bytes long. The total length of a domain name cannot exceed 255 bytes, including the dots.
* 对报文分片，每一个分片都是一个query
*/
struct QueryPkg * buildQuerys_v2(const char * payload, int len, int * pkgNum)
{
    #define MAX_LABEL_BYTES 63
    const unsigned int MAX_PAYLOAD_SIZE_PER_QUERY = base32decsize(MAX_LABEL_BYTES) - sizeof(struct FragmentCtrlv2); //35
    /* 把每个分片都作为一个query */
    int split_num = len / MAX_PAYLOAD_SIZE_PER_QUERY;
    int restBytes = len % MAX_PAYLOAD_SIZE_PER_QUERY;
    if (restBytes == 0)
    {
        *pkgNum = split_num;
        restBytes = MAX_PAYLOAD_SIZE_PER_QUERY;
    }
    else
    {
        *pkgNum = split_num + 1;
    }
        
    struct QueryPkg * pkgs = (struct QueryPkg *)malloc(sizeof(struct QueryPkg)*(split_num + 1));
    for (int i = 0; i < *pkgNum; i++)
    {
        const char * p = payload + i*MAX_PAYLOAD_SIZE_PER_QUERY;
        int outlen = 0;
        char * out = 0;
        unsigned short seqId = 0;
        int isFirst = (i == 0);
        int isLast = (i == *pkgNum - 1);
        if(!isLast)
        {
            out = buildQuery_V2(p, MAX_PAYLOAD_SIZE_PER_QUERY, isFirst, 0, &seqId, &outlen);
        }
        else
        {
            out = buildQuery_V2(p, restBytes, isFirst, 1, &seqId, &outlen);
        }
        
        pkgs[i].seqId = seqId;
        pkgs[i].payload = out;
        pkgs[i].len = outlen;
    }
    return pkgs;
}

/*
* client使用
* 解析响应包
* 返回值是入参的偏移
*/
char * parseResponse(const char * packet, int len, int * outlen)
{
    if (len <= sizeof(struct DNS_HEADER))
    {
        return 0;
    }
    
    struct DNS_HEADER * head = (struct DNS_HEADER *)packet;
    if (head->qr == 1 && head->rcode == 0)
    {
        char * p = (char *)(head + 1);
        p += strlen(p) + 1;//query中的域名
        p += sizeof(struct QUESTION);

        unsigned char c = p[0];
        //answer中是否是压缩域名
        if ((c & 0xc0) == 0xc0)
        {
            p += 2;//这里是2字节的偏移
        }
        else
        {
            p += strlen(p) + 1;//answer中的域名
        }
        
        if (p - packet >= len)
        {
            return 0;
        }
        
        struct R_DATA * answer = (struct R_DATA *)p;
        unsigned short answer_type = ntohs(answer->type);
        if(answer_type == QUERY_A)
        {
            *outlen = ntohs(answer->data_len);
            return answer->rdata;
        }
        else if (answer_type == QUERY_DNSKEY)
        {
            struct DNSKEY_ANSWER_PAYLOAD * dnskey = (struct DNSKEY_ANSWER_PAYLOAD *)answer->rdata;
            char alg = dnskey->algorithm;
            unsigned short flags = ntohs(dnskey->flags);  
            char protocol = dnskey->protocol;
            if (protocol == 3 && flags == 0x100 && alg == 7)
            {
                *outlen = ntohs(answer->data_len) - sizeof(*dnskey);
                return dnskey->publicKey;
            }
        }
    }

    debug("parseResponse: dns head id %d rsp fmt unexpected.\n", ntohs(head->id));

    return 0;
}

