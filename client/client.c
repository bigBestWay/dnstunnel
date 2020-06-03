#include <stdio.h>
#include "app.h"
#include "util.h"
#include "udp.h"
#include "cmd.h"
/*
* client端定时询问server，是否有命令需要执行
*/

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

        struct Cmd * cmd = (struct Cmd *)msg;
        len = handleCmd(cmd, msg, sizeof(msg));
        if (len > 0)
        {
            len = client_send(fd, msg, len);
            printf("sent %d\n", len);
        }

        sleep(1);
    }
        
    return 0;
}