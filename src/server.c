#include "../inc/server.h"
#include <dlfcn.h>
#include <openssl/err.h>
void Server() {
  void *networkHandler = dlopen("/usr/lib", RTLD_LAZY),
       *packetHandler = dlopen("/usr/lib", RTLD_LAZY),
       *cryptHandler = dlopen("/usr/bin", RTLD_LAZY),
       *dbHandler = dlopen("/usr/bin", RTLD_LAZY);
  Network networkFunc = dlsym(networkHandler, "networkFunc");
  ThreadFunc packetThreadFunc = dlsym(packetHandler, "packetThreadFunc");
  ThreadFunc cryptThreadFunc = dlsym(cryptHandler, "cryptThreadFunc");
  ThreadFunc dbThreadFunc = dlsym(dbHandler, "dbThreadFunc");
  pthread_t PacketThread, CryptThread, DbThread;
  pthread_create(&PacketThread, 0, packetThreadFunc, (void *)NULL);
  pthread_create(&CryptThread, 0, cryptThreadFunc, (void *)NULL);
  pthread_create(&DbThread, 0, dbThreadFunc, (void *)NULL);
  SSL_CTX *ctx;
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  ctx = SSL_CTX_new(TLS_server_method());
  if (ctx == NULL) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }

  if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(1);
  }
  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr, "X509 certificate not match");
    exit(1);
  }
  networkFunc(ctx);
}
