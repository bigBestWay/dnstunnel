#ifndef __SESSION_H__
#define __SESSION_H__

typedef struct
{
    unsigned short clientid;
    int datafd;
    int cmdfd;
    unsigned int ip;
    int state;
    char hostname[255];
}SessionEntry;

typedef struct
{
    const SessionEntry * list[65536];
    int size;
}SessionList;

int get_session_state(unsigned short clientid);

void set_session_state(unsigned short clientid, int state);

void session_init();

int add_session(unsigned short clientid, const SessionEntry * new_entry);

void delete_session(unsigned short clientid);

int get_data_fd(unsigned short clientid);

int get_cmd_fd(unsigned short clientid);

SessionList live_sessions();

void set_session_hostinfo(unsigned short clientid, const char * hostname, unsigned int ip);

#endif
