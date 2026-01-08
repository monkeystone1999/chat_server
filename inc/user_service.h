#ifndef USR_SERV_H
#define USR_SERV_H

#include <netinet/in.h>

int find_usr(int sock, struct sockaddr_in *client_addr);
int find_ip(int sock, struct sockaddr_in *client_addr);
/// db 를 가져올 때
int init_db(char *db_name);
#endif
