#include "../inc/server.h"
#include <dlfcn.h>

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
  networkFunc();
}
