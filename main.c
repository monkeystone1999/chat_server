#include <dlfcn.h>
/// 최종 목표 : 다중 사용자 채팅 서버
/// 현재로써는 서버에서 채팅을 진행하게 한다.
/// 일단은 서버가 통신을 받는 것부터 시작
int main(int argc, char **argv) {
  typedef void (*ServerFunc)();
  void *Handler;
  Handler = dlopen("/usr/bin", RTLD_GLOBAL);
  ServerFunc Server = dlsym(Handler, "Server");
  Server();
  return 0;
}
