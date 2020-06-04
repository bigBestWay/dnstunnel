#include <stdio.h>
#include "app.h"
#include "util.h"
#include "udp.h"
#include "cmd.h"
/*
* client端定时询问server，是否有命令需要执行
*/

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
            }
        }while(!feof(fp));
        fclose(fp);
    }
}

int main()
{
    client_app_init();

    char dns_server_ip[255];
    get_sys_nameserver(dns_server_ip, sizeof(dns_server_ip));

    int fd = udp_connect(dns_server_ip, 53);
    if(fd == -1)
    {
        perror("udp connect fail");
        return 1;
    }

    while(1){
        char msg[65536] = {0};
        int len = client_recv(fd, msg, sizeof(msg));
        printf("recv %d %s\n", len, msg);

        struct CmdReq * cmd = (struct CmdReq *)msg;
        len = handleCmd(cmd, msg, sizeof(msg));
        if (len > 0)
        {
            len = client_send(fd, msg, len);
            printf("sent %d\n", len);
        }

        delay(1, 0);
    }
        
    return 0;
}