#ifndef _APP_H_
#define _APP_H_
#include "../include/cmd.h"

int isHello(const struct CmdReq * cmd);
/*
* 应用层协议封装，完成可靠传输
*/
int server_recv(int fd, char * buf, int len);

//len长度必须大于4，否则失败
int server_send(int fd, const char * p, int len);

#endif
