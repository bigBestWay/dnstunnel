#include "../include/dns.h"
#include "../include/base32.h"
#include "../include/util.h"
#include <memory.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

/*
* server使用
* 对查询分片进行处理，获得报文，写入out最大也只有45字节
*/
int processQuery(const char * payload, int len, char * out, int outsize)
{
    struct DNS_HEADER * head = (struct DNS_HEADER *)payload;
    //有时这个附加选项会被删掉，因此不强求附加选项
    if (ntohs(head->q_count) == 1)
    {
        char tmp[255] = {0};
        char * p = (char *)(head + 1);
        struct QUESTION * question = (struct QUESTION *)(p + strlen(p) + 1);
        unsigned short qtype = ntohs(question->qtype);
        if (qtype != QUERY_A && qtype != QUERY_DNSKEY)
        {
            return -1;
        }
        
        for(int i = 0; i < p[0]; ++i)
        {
            tmp[i] = p[i+1];
        }

        //printf("before base32 decode: %s\n", tmp);
        int decodeLen = base32_decode(tmp, out, outsize);
        //dumpHex(out, decodeLen);
        if (decodeLen <= 0 || decodeLen <= sizeof(struct FragmentCtrl))//解密失败，有时会发来ntp之类的数据
        {
            debug("base32_decode %s error.\n", tmp);
            return -1;
        }
        
        return decodeLen;
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
    
    *ip = (*value);

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
    //pulibckey最大长度为437
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
