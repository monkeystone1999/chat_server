#ifndef _SERVER_H_
#define _SERVER_H_
#include <dlfcn.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdlib.h>
typedef void *(*ThreadFunc)(void *);
typedef void (*Network)(SSL_CTX *ctx);
void Server();
int addHandler(const char *libName);
#endif
