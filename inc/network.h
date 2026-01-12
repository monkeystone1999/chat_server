#ifndef _NET_H_
#define _NET_H_
#include <arpa/inet.h>
#include <fcntl.h>
#include <memory.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
void networkFunc(SSL_CTX *ctx);
#endif
