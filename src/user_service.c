#include "../inc/user_service.h"
#include <arpa/inet.h>
#include <err.h>
#include <memory.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <unistd.h>
#define USR_INIT_NUM 40
struct user_table usr_table;

typedef struct {
  char ip[INET_ADDRSTRLEN];
  int key;
  int port;
} ip_info;

typedef struct {
  ip_info *ip;
  char usr_name[20];
  bool state; // == is_online
} user_info;

struct user_table {
  user_info *usr_info;
  int size;
  int capa;
};

int get_empty_locate() {
  for (int i = 0; i < usr_table.size; ++i) {
    if (usr_table.usr_info[i].state == false) {
      return i;
    }
  }
  return -1;
}

int find_usr(int sock, struct sockaddr_in *client_addr) {
  int size = usr_table.size;
  char usr_name[20];
  int res = read(sock, usr_name, 20);
  if (res == -1) {
    perror("read Fail");
    exit(1);
  }
  for (int i = 0; i < size; ++i) {
    if (strncmp(usr_table.usr_info->usr_name, usr_name, 20) == 0) {
      return 0;
    }
  }
  return -1;
};

int find_ip(int sock, struct sockaddr_in *client_addr) {
  int size = usr_table.size;
  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &client_addr->sin_addr, ip, INET_ADDRSTRLEN);
  for (int i = 0; i < size; ++i) {
    if (strncmp(usr_table.usr_info->ip, ip, INET_ADDRSTRLEN) == 0) {
      return 0;
    }
  }
  return -1;
};

int add_ip(struct sockaddr_in *client_addr) {
  int index = get_empty_locate();
  char ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &client_addr->sin_addr, ip, INET_ADDRSTRLEN);
  memcpy(usr_table.usr_info[index].ip, '\0', INET_ADDRSTRLEN);
  snprintf(usr_table.usr_info[index].ip, INET_ADDRSTRLEN, "%s", ip);
  usr_table.usr_info[index].state = true;
  return 0;
}

void __attribute__((constructor)) init_manager() {
  usr_table.usr_info = (user_info *)malloc(sizeof(user_info) * USR_INIT_NUM);
  usr_table.size = USR_INIT_NUM;
  for (int i = 0; i < USR_INIT_NUM; ++i) {
    usr_table.usr_info[i].ip = (user_info *)malloc(sizeof(user_info));
    usr_table.usr_info[i].state = false;
  }
}
