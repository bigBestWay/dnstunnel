#ifndef _APP_H_
#define _APP_H_

void client_app_init();
/*
* 应用层协议封装，完成可靠传输
*/
int client_send(int fd, const char * p, int len);

int client_recv(int fd, char * p, int len);

#endif
