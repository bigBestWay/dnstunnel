#ifndef _DNS_H_
#define _DNS_H_

#define MAX_DOMAINNAME_BYTES 255

struct DNS_HEADER {
    unsigned short id; //会话标识
    unsigned char rd :1; // 表示期望递归
    unsigned char tc :1; // 表示可截断的 
    unsigned char aa :1; //  表示授权回答
    unsigned char opcode :4; 
    unsigned char qr :1; //  查询/响应标志，0为查询，1为响应
    unsigned char rcode :4; //应答码
    unsigned char cd :1; 
    unsigned char ad :1; 
    unsigned char z :1; //保留值
    unsigned char ra :1; // 表示可用递归
    unsigned short q_count; // 表示查询问题区域节的数量 
    unsigned short ans_count; // 表示回答区域的数量
    unsigned short auth_count; // 表示授权区域的数量
    unsigned short add_count; // 表示附加区域的数量
};

/*
**DNS报文中查询问题区域
*/
struct QUESTION {
    unsigned short qtype;//查询类型
    unsigned short qclass;//查询类
};

#pragma pack(push, 1)//保存对齐状态，设定为1字节对齐
struct EDNS0_OPT_RR
{
    char name[1];
    unsigned short type;
    unsigned short udp_size;
    char extendRTcode;
    char ednsVersion;
    unsigned short z_flag;
    unsigned short data_len;
    char rdata[0];
};

#pragma pack(pop) //恢复对齐状态

struct EDNS0_OPT_RR_OPTION
{
     unsigned short code;
     unsigned short length;
     char data[0];
};

/*
**DNS报文中回答区域的常量字段 
*/
//编译制导命令
#pragma pack(push, 1)//保存对齐状态，设定为1字节对齐
struct R_DATA {
    unsigned short type; //表示资源记录的类型
    unsigned short _class; //类
    unsigned int ttl; //表示资源记录可以缓存的时间
    unsigned short data_len; //数据长度
    char rdata[0];
};

/* 属于rdata内容 */
struct DNSKEY_ANSWER_PAYLOAD
{
    unsigned short flags;
    char protocol;
    char algorithm;
    char publicKey[0];
};

struct RRSIG_ANSWER_PAYLOAD
{
    unsigned short cover_type;
    char algorithm;
    char labels;
    int origianlTTL;
    int signature_expire;
    int signature_inception;
    short keyTag;
    char signame[0];
    //后接变长的名字,signature name
    //再接signature
};

struct FragmentCtrlv2
{
    unsigned short end:1;
    unsigned short begin:1;
    unsigned short seqId:14;
    unsigned short clientID;
};

#pragma pack(pop) //恢复对齐状态

struct QueryPkg
{
    unsigned short seqId;
    unsigned short len;
    char * payload;
};

typedef enum 
{
    QUERY_A = 1,
    QUERY_DNSKEY = 48
}QUERY_TYPE;

#define GET_NEXT_SEQID(id) (((short)(id + 1)) < 0? 0: ((short)(id + 1)))
#define GET_NEXT_SEQID_V2(id) (((short)(id + 1)) == 0x3fff ? 0: ((short)(id + 1)))

/** client 使用 **/
struct QueryPkg * buildQuerys_v2(const char * payload, int len, int * pkgNum);
int processQuery(const char * payload, int len, char * out, int outsize);
char * parseResponse(const char * packet, int len, int * outlen);

/** server 使用 **/
char * buildResponseA(const char * query, int len, unsigned int * value, int * outlen);
char * buildResponseDnskey(const char * query, int len, const char * payload, int payloadlen, int * outlen);

#endif
