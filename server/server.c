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
*/

static struct
{
    const char * cmd;
    const char * argv[5];
}g_cmdUsageTable[] = {
    {0, {0, 0, 0, 0, 0}},
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
    {"pwd", {0, 0, 0, 0, 0}}
};

//0 没有命令
static unsigned char findCmd(const char * cmd, int * argc)
{
    for (int i = 1; i < sizeof(g_cmdUsageTable)/sizeof(g_cmdUsageTable[0]); i++)
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
    return 0;
}

static void usage()
{
    for (int i = 1; i < sizeof(g_cmdUsageTable)/sizeof(g_cmdUsageTable[0]); i++)
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
            perror("Local error:");
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

static void parseCmdRsp(const struct CmdReq * req, const char * data, int len)
{
    struct CmdRsp * rsp = (struct CmdRsp *)data;
    unsigned int datalen = ntohl(rsp->datalen);
    if (datalen > len)
    {
        printf("Recv CmdRsp length error\n");
        return;
    }
    
    if (rsp->errNo == CUSTOM_ERRNO)
    {
        rsp->data[datalen] = 0;
        printf("Remote error: %s.\n", rsp->data);
    }
    else if(rsp->errNo != 0)
    {
        const char * errMsg = strerror(rsp->errNo);
        printf("Remote error: %s.\n", errMsg);
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
                        perror("writeFile");
                    }
                    else
                    {
                        printf("Download remote %s to %s success\n", remoteName, localName);
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
                printf("uncompress %d, rsplen %d\n", ret, datalen);
            }
            free(plain);
        }
        else
        {
            rsp->data[datalen] = 0;
            printf("\n%s\n", rsp->data);
        }
    }
}

static void * handleTraffic(void * arg)
{
    int pipeFd = *((int *)arg);
    int fd = udp_bind(53);
    if (fd == -1)
    {
        return 0;
    }

    char dataReq[65536];
    char dataRsp[1024*1024];
    while(1)
    {
        int datalen = 0;
        int hasData = wait_data(pipeFd, 0);

        if (hasData == 1)
        {
            datalen = read(pipeFd, dataReq, sizeof(dataReq));
            if (datalen <= 0)
            {
                perror("read");
                continue;
            }
        }
        else if(hasData == 0)
        {
            ((struct CmdReq *)dataReq)->code = 0;
            datalen = 8;
        }
        
        char addr[1][16] = {0};
        int ret = server_send(fd, dataReq, datalen, addr);
        if(ret <= 0)
        {
            perror("server_send");
        }

        if (hasData)
        {
        recv:
            ret = server_recv(fd, dataRsp, sizeof(dataRsp), addr);
            if(ret > 0)
            {
                struct CmdReq * req = (struct CmdReq *)dataReq;
                struct CmdRsp * rsp = (struct CmdRsp *)dataRsp;
                if(rsp->sid != req->sid)
                    goto recv;

                parseCmdRsp(req, dataRsp, ret);
                write(1, ">>", 2);
            }
        }
    }
}

int main()
{
    setbuf(stdout, 0);

    int fds[2];
    if(pipe(fds) != 0)
    {
        perror("pipe");
        return 1;
    }

    pthread_t tid = 0;
    pthread_create(&tid, NULL, handleTraffic, &fds[0]);

    while (1)
    {
        char buffer[65536] = {0};
        write(1, ">>", 2);
        read(0, buffer, sizeof(buffer));

        //最多5个参数
        char * argv[6] = {0};
        int argc1 = 0, argc2 = 0;
        argc1 = parseCmdLine(buffer, argv);//包括了命令自身
        if (argc1 == 0)
        {
            continue;
        }
        
        unsigned char code = findCmd(argv[0], &argc2);
        if (code == 0)
        {
            usage();
            continue;
        }
        
        if (argc1 - 1 < argc2)
        {
            help(code);
            continue;
        }
        
        int len = buildCmdReq(code, argv, argc1, buffer, sizeof(buffer));
        if (len <= 0)
        {
            continue;
        }
            
        len = write(fds[1], buffer, len);
        if (len <=0 )
        {
            perror("write");
        }
    }
    
    return 0;
}