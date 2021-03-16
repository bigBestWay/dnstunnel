#ifndef _APP_H_
#define _APP_H_
#include "../include/cmd.h"

int isHello(struct CmdReq * cmd);

int is_session_establish_sync(struct CmdReq * cmd);

unsigned short key_parse(const struct CmdReq * cmd);

/*
* 应用层协议封装，完成可靠传输
*/
int server_recv_v2(int fd, char * buf, int len, unsigned short key);

//len长度必须大于4，否则失败
int server_send_v2(int fd, const char * p, int len, unsigned short * key);

#endif
