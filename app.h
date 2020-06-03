#ifndef _APP_H_
#define _APP_H_

void client_app_init();
/*
* 应用层协议封装，完成可靠传输
*/
int client_send(int fd, const char * p, int len);

int client_recv(int fd, char * p, int len);

int server_recv(int fd, char * buf, int len, char (*addr)[16]);

//len长度必须大于4，否则失败
int server_send(int fd, const char * p, int len, char (*addr)[16]);

#endif
