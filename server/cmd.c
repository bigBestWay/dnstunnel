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

int s_currentSession = -1;

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
static int findCmd(const char * cmd, int * argc)
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

static void usage()
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

static void help(int code)
{
    printf("Usage: %s", g_cmdUsageTable[code].cmd);
    for (int j = 0; j < sizeof(g_cmdUsageTable[code].argv)/sizeof(char *) && g_cmdUsageTable[code].argv[j]; j++)
    {
        printf(" %s", g_cmdUsageTable[code].argv[j]);
    }
    printf("\n");
}

static int parseCmdLine(char * cmdline, char *argv[])
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

static int buildCmdReq(unsigned char code, const char *argv[], int argc, char * out, int maxSize)
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

void parseCmdRsp(const struct CmdReq * req, const char * data, int len)
{
    struct CmdRsp * rsp = (struct CmdRsp *)data;
    unsigned int datalen = ntohl(rsp->datalen);
    if (datalen > len)
    {
        printf("\nRecv CmdRsp length error\n");
        return;
    }
    
    if (rsp->errNo == CUSTOM_ERRNO)
    {
        rsp->data[datalen] = 0;
        printf("\nRemote error: %s.\n", rsp->data);
    }
    else if(rsp->errNo != 0)
    {
        const char * errMsg = strerror(rsp->errNo);
        printf("\nRemote error: %s.\n", errMsg);
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
                        printf("\nDownload remote %s to %s success\n", remoteName, localName);
                    }
                }
                else
                {
                    plain[plainLen] = 0;
                    printf("\n%s\n", plain);
                }
            }
            else
            {
                printf("\nuncompress %d, rsplen %d\n", ret, datalen);
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
                printf("\nhostname:%s,ip:%s\n", hostname, ipv4);
            }
            else
            {
                rsp->data[datalen] = 0;
                printf("\n%s\n", rsp->data);
            }
        }
    }
}

static void UI_waiting()
{
    static char ch = '|';
    //rewind(stdout);
    //ftruncate(1, 0);
    switch (ch)
    {
    case '|':
        ch = '/';
        break;
	case '/':
		ch = '-';
		break;
    case '-':
        ch = '\\';
        break;
    case '\\':
        ch = '|';
    default:
        break;
    }
    write(1, &ch, 1);
}

void startUI()
{
    while (1)
    {
        SessionList sessionList = live_sessions();
        if (sessionList.size == 0)
        {
            UI_waiting();
            delay(0, 1000);
            fputs("\033[1D", stdout);
            continue;
        }

        if (s_currentSession < 0) //如果未选择session，默认指定第一个
        {
            s_currentSession = sessionList.list[0]->clientid;
        }
        else
        {
            int valid = 0;
            for (int i = 0; i < sessionList.size; i++)
            {
                if (sessionList.list[i]->clientid == s_currentSession)
                {
                    valid = 1;
                    break;
                }
            }

            if (!valid)
            {
                printf("session %d not valid\n", s_currentSession);
                s_currentSession = sessionList.list[0]->clientid;
            }
        }
        
        printf("Session[%d]>>", s_currentSession);
        char buffer[65536] = {0};
        read(0, buffer, sizeof(buffer));
        //最多5个参数
        char * argv[6] = {0};
        int argc1 = 0, argc2 = 0;
        argc1 = parseCmdLine(buffer, argv);//包括了命令自身
        if (argc1 == 0)
        {
            continue;
        }
        
        int result = findCmd(argv[0], &argc2);
        if (result < 0)
        {
            usage();
            continue;
        }
        
        if (argc1 - 1 < argc2)
        {
            help(result);
            continue;
        }

        if (result == 0)//session管理命令
        {
            if (strcmp(argv[1], "list") == 0)
            {
                SessionList sessionList = live_sessions();
                printf("clientid\tip\thostname\t\n");
                const char * fmt = "%d\t%s\t%s\n";
                for (int i = 0; i < sessionList.size; i++)
                {
                    struct in_addr addr;
                    addr.s_addr = sessionList.list[i]->ip;
                    char * ipv4 = inet_ntoa(addr);
                    printf(fmt, sessionList.list[i]->clientid, ipv4, sessionList.list[i]->hostname);
                }
            }
            else
            {
                int arg = atoi(argv[1]);
                s_currentSession = arg;
            }
            continue;
        }
        
        
        unsigned char code = result;
        int len = buildCmdReq(code, argv, argc1, buffer, sizeof(buffer));
        if (len <= 0)
        {
            continue;
        }
        
        int cmdfd = get_cmd_fd(s_currentSession);
        if (cmdfd < 0)
        {
            perror("get_cmd_fd");
            continue;
        }
        
        len = write(cmdfd, buffer, len);
        if (len <=0 )
        {
            perror("write");
        }
    }
}
