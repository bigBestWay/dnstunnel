#include<string.h>    
#include<stdlib.h>    
#include<sys/socket.h>    
#include<arpa/inet.h> 
#include<netinet/in.h>
#include<unistd.h>
#include<stdio.h>

int udp_connect(const char *ip, short port)
{
    struct sockaddr_in server;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(fd == -1)
    {
        return -1;
    }

    bzero(&server, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);

    if(connect(fd, (struct sockaddr *)&server, sizeof(server)) == -1)
    {
        return -1;
    }

    return fd;
}

int udp_bind(short port)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) 
    {
        return -1;
    }

    struct sockaddr_in local_sa;
    local_sa.sin_family = AF_INET;
    local_sa.sin_port = htons(port);
    local_sa.sin_addr.s_addr = INADDR_ANY;

    int res = bind(sockfd, (struct sockaddr *)&local_sa, sizeof(struct sockaddr));
    if (res == -1) {
        perror("bind:");
        return -1;
    }

    return sockfd;
}

/*
* 等待数据
* 返回值 0 超时 1 数据到达 -1 出错
*/
int wait_data(int fd, int timeout)
{
    struct timeval tv = {timeout, 0};
    fd_set readfds;

    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    int ret = select(fd + 1, &readfds, NULL, NULL, &tv);
    if(ret == 0)//timeout
    {
        return 0;
    }
    else if (ret < 0)
    {
        return -1;
    }
    
    if(FD_ISSET(fd, &readfds))
    {
        return 1;
    }
    return -1;
}

int wait_data2(int fd, int tv_usec)
{
    struct timeval tv = {0, tv_usec};
    fd_set readfds;

    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    int ret = select(fd + 1, &readfds, NULL, NULL, &tv);
    if(ret == 0)//timeout
    {
        return 0;
    }
    else if (ret < 0)
    {
        return -1;
    }
    
    if(FD_ISSET(fd, &readfds))
    {
        return 1;
    }
    return -1;
}

int udp_recv(int fd, char * buffer, int bufferlen, char (*addr)[16])
{
    socklen_t addrlen = sizeof(struct sockaddr_in);
    return recvfrom(fd, buffer, bufferlen, 0, (struct sockaddr*)addr, &addrlen);
}

int udp_send(int fd, char * buffer, int bufferlen, char (*addr)[16])
{
    socklen_t addrlen = sizeof(struct sockaddr_in);
    return sendto(fd, buffer, bufferlen, 0, (struct sockaddr*)addr, addrlen);
}
