#ifndef _UDP_H_
#define _UDP_H_

int udp_connect(const char *ip, short port);

int udp_bind(short port);

int udp_send(int fd, char * buffer, int bufferlen, char (*addr)[16]);

int udp_recv(int fd, char * buffer, int bufferlen, char (*addr)[16]);

int wait_data(int fd, int timeout);

/* 微秒级延时 */
int wait_data2(int fd, int tv_usec);

#endif