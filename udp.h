#ifndef _UDP_H_
#define _UDP_H_

int udp_connect(const char *ip, short port);

int udp_bind(short port);

int udp_send(int fd, char * buffer, int bufferlen, char (*addr)[16]);

int udp_recv(int fd, char * buffer, int bufferlen, char (*addr)[16]);

int wait_data(int fd, int timeout);

#endif