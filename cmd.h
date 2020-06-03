#ifndef _CMD_H_
#define _CMD_H_

#pragma pack(push, 1)
struct Cmd
{
    unsigned char code;
    unsigned short datalen;
    char data[0];
};
#pragma pack(pop)

#define CLIENT_CMD_HELLO 0xff
struct Hello
{
    char msg[4]; //固定为HALO
    unsigned short key;
    char reserve[2];
};

struct CmdAckPayload
{
    unsigned short seqid;
    char ok[2];//固定为字母OK
};

/****************************** 下面是底层无关的命令 *******************************/
enum ServerCmdId
{
    SERVER_CMD_NOTHING = 0,
    SERVER_CMD_GETUID ,
    SERVER_CMD_UPLOAD ,
    SERVER_CMD_DOWNLOAD ,
    SERVER_CMD_EXECUTE ,
    SERVER_CMD_MOVE ,
    SERVER_CMD_MKDIR ,
    SERVER_CMD_DELDIR ,
    SERVER_CMD_RENAME ,
    SERVER_CMD_LIST ,
    SERVER_CMD_DELFILE ,
    SERVER_CMD_CHDIR,
    SERVER_CMD_GETCWD,
    SERVER_CMD_END = 255
};

int handleCmd(const struct Cmd * cmd, char * out, int maxSize);

#endif