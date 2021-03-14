#ifndef _APP_H_
#define _APP_H_

void clientid_sequid_init();

void clientid_sequid_init_v2();
/*
* 应用层协议封装，完成可靠传输
*/
int client_send(int fd, const char * p, int len);

int client_send_v2(int fd, const char * p, int len);

int client_recv(int fd, char * p, int len);

int client_recv_v2(int fd, char * p, int len);

#endif
