#ifndef _CMD_H_
#define _CMD_H_

#pragma pack(push, 1)
struct CmdReq
{
    unsigned char code; //命令码
    unsigned short sid; //会话id，一次输入输出称为一次会话
    unsigned short datalen;
    char data[0];
};

#define CUSTOM_ERRNO 0xFF

struct CmdRsp
{
    unsigned char flag; //0x1 压缩
    unsigned char errNo;//linux标准errno,如果为0xff表示自定义错误
    unsigned short sid;
    unsigned int datalen;
    char data[0];
};

struct Hello
{
    unsigned short key;
    char msg[4]; //固定为HALO
    unsigned int timestamp;
};

struct NewSession
{
    unsigned short key;
    char magic[4];//固定为0xdeadcafe
    unsigned int timestamp;
};
#pragma pack(pop)

struct CmdAckPayload
{
    char ok[2];//固定为字母OK
    unsigned short seqid;
};

/****************************** 下面是底层无关的命令 *******************************/
enum ServerCmdId
{
    SERVER_CMD_NOTHING = 0,
    SERVER_CMD_GETUID ,
    SERVER_CMD_UPLOAD ,
    SERVER_CMD_DOWNLOAD,
    SERVER_CMD_SHELL ,
    SERVER_CMD_MOVE ,
    SERVER_CMD_MKDIR ,
    SERVER_CMD_DELDIR ,
    SERVER_CMD_RENAME ,
    SERVER_CMD_LIST ,
    SERVER_CMD_DELFILE ,
    SERVER_CMD_CHDIR,
    SERVER_CMD_GETCWD,
    SERVER_CMD_GETOUTERIP,
    SERVER_CMD_REVERSESHELL,

    SERVER_CMD_NEWSESSION_SYNC = 0xfd,
    SERVER_CMD_HELLo = 0xfe,
    SERVER_CMD_END = 0xff
};

int handleCmd(const struct CmdReq * cmd, char * out, int maxSize);

int buildCmdReq(unsigned char code, const char *argv[], int argc, char * out, int maxSize);

int findCmd(const char * cmd, int * argc);

int parseCmdLine(char * cmdline, const char *argv[]);

void help(int code);

void usage();

#endif