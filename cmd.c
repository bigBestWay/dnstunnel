#include "cmd.h"
#include "sys/types.h"
#include "util.h"
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdio.h>
#include "zlib.h"
#include <stdlib.h>

typedef int (*CMD_HANDLE)(const void * in, int len, char * out, int maxSize);

static int process_getuid(const void * in, int len, char * out, int maxSize);
static int process_upload(const void * in, int len, char * out, int maxSize);
static int process_download(const void * in, int len, char * out, int maxSize);
static int process_execute(const void * in, int len, char * out, int maxSize);
static int process_move(const void * in, int len, char * out, int maxSize);
static int process_mkdir(const void * in, int len, char * out, int maxSize);
static int process_del_dir(const void * in, int len, char * out, int maxSize);
static int process_rename(const void * in, int len, char * out, int maxSize);
static int process_list(const void * in, int len, char * out, int maxSize);
static int process_del_file(const void * in, int len, char * out, int maxSize);
static int process_chdir(const void * in, int len, char * out, int maxSize);
static int process_getcwd(const void * in, int len, char * out, int maxSize);

static CMD_HANDLE g_cmdTable[256] = {
    0,
    process_getuid, //SERVER_CMD_GETUID
    process_upload, //SERVER_CMD_UPLOAD
    process_download,//SERVER_CMD_DOWNLOAD
    process_execute,//SERVER_CMD_EXECUTE
    process_move,//SERVER_CMD_MOVE
    process_mkdir,//SERVER_CMD_MKDIR
    process_del_dir,//SERVER_CMD_DELDIR
    process_rename,//SERVER_CMD_RENAME
    process_list,//SERVER_CMD_LIST
    process_del_file,//SERVER_CMD_DELFILE
    process_chdir, //SERVER_CMD_CHDIR
    process_getcwd,//SERVER_CMD_GETCWD
};

#define GET_CMD_HANDLE(code) g_cmdTable[code]

int handleCmd(const struct CmdReq * cmd, char * out, int maxSize)
{
    CMD_HANDLE handle = GET_CMD_HANDLE(cmd->code);
    if (handle)
    {
        unsigned short datalen = ntohs(cmd->datalen);
        struct CmdRsp * rsp = (struct CmdRsp *)out;
        rsp->flag = 0;
        rsp->sid = cmd->sid;
        int payloadLen = handle(cmd->data, datalen, rsp->data, maxSize - sizeof(*rsp));
        if (handle == process_list)//对数据进行压缩
        {
            char * plain = (char *)malloc(payloadLen);
            memcpy_s(plain, payloadLen, rsp->data, payloadLen);

            unsigned long compressedLen = maxSize - sizeof(*rsp);
            int ret = compress(rsp->data, &compressedLen, plain, payloadLen);
            if(ret == Z_OK)
            {
                printf("orignal %d, after compress %ld\n", payloadLen, compressedLen);
                rsp->flag = 1;
                rsp->datalen = htons(compressedLen);
                payloadLen = compressedLen;
            }

            free(plain);
        }

        rsp->datalen = htons(payloadLen);
        return sizeof(*rsp) + payloadLen;
    }
    return 0;
}

static int reply_errMsg(char * out, int maxSize)
{
    char * errMsg = strerror(errno);
    int len = strlen(errMsg);
    memcpy_s(out, maxSize, errMsg, len + 1);
    return len;
}

static int process_getuid(const void * in, int len, char * out, int maxSize)
{
    //in???
    int uid = getuid();
    struct passwd * my_info = getpwuid(uid);
    struct group * grp_info = getgrgid(my_info->pw_gid);
    if(my_info == 0 || grp_info == 0)
        return 0;

    const char * fmt = "uid=%d(%s) gid=%d(%s)";
    return snprintf(out, maxSize, fmt, my_info->pw_uid, my_info->pw_name, my_info->pw_gid, grp_info->gr_name);
}

static int process_upload(const void * in, int len, char * out, int maxSize)
{
    return 0;
}

static int process_download(const void * in, int len, char * out, int maxSize)
{
    return 0;
}
static int process_execute(const void * in, int len, char * out, int maxSize)
{
    const char * exePath = (const char * )in;
    if (fork() == 0)
    {
        if (fork() == 0)
        {
            
        }
    }
    
    return 0;
}
static int process_move(const void * in, int len, char * out, int maxSize)
{
    return 0;
}
static int process_mkdir(const void * in, int len, char * out, int maxSize)
{
    const char * dir = (const char *)in;
    if (mkdir(dir, S_IRUSR | S_IWUSR | S_IXUSR) == 0)
    {
        #define SUCCESS_LEN 8
        memcpy_s(out, maxSize, "Success", SUCCESS_LEN);
        return SUCCESS_LEN;
    }
    else
    {
        return reply_errMsg(out, maxSize);
    }
    return 0;
}
static int process_del_dir(const void * in, int len, char * out, int maxSize)
{
    const char * dir = (const char *)in;
    if (rmdir(dir) == 0)
    {
        #define SUCCESS_LEN 8
        memcpy_s(out, maxSize, "Success", SUCCESS_LEN);
        return SUCCESS_LEN;
    }
    else
    {
        return reply_errMsg(out, maxSize);
    }
}
static int process_rename(const void * in, int len, char * out, int maxSize)
{
    const char * oldname = (const char *)in;
    const char * newname = (const char *)in + strlen(oldname) + 1;
    if (rename(oldname, newname) == 0)
    {
        #define SUCCESS_LEN 8
        memcpy_s(out, maxSize, "Success", SUCCESS_LEN);
        return SUCCESS_LEN;
    }
    else
    {
        return reply_errMsg(out, maxSize);
    }
}
static int process_list(const void * in, int len, char * out, int maxSize)
{
    FILE * fp = popen("ls -lrt", "r");
    if (fp)
    {
        int id = 0;
        do
        {
            out[id++] = fgetc(fp);
        } while (!feof(fp) && id < maxSize);
        fclose(fp);
        return id;
    }
    
    #define FAILURE_LEN 8
    memcpy_s(out, maxSize, "Failure", FAILURE_LEN);
    return FAILURE_LEN;
}
static int process_del_file(const void * in, int len, char * out, int maxSize)
{
    const char * filePath = (const char *)in;
    if (unlink(filePath) == 0)
    {
        #define SUCCESS_LEN 8
        memcpy_s(out, maxSize, "Success", SUCCESS_LEN);
        return SUCCESS_LEN;
    }
    else
    {
        return reply_errMsg(out, maxSize);
    }
}
static int process_chdir(const void * in, int len, char * out, int maxSize)
{
    const char * dir = (const char *)in;
    if (chdir(dir) == 0)
    {
        #define SUCCESS_LEN 8
        memcpy_s(out, maxSize, "Success", SUCCESS_LEN);
        return SUCCESS_LEN;
    }
    else
    {
        return reply_errMsg(out, maxSize);
    }
}
static int process_getcwd(const void * in, int len, char * out, int maxSize)
{
    //in not in use
    char * ret = getcwd(out, maxSize);
    if (ret == 0)
    {
        return reply_errMsg(out, maxSize);
    }
    
    return strlen(ret);
}