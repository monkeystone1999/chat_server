#include "../inc/network.h"
#include "../inc/thread_pool.h"
#include "../inc/user_service.h"
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
SSL_CTX *server_ctx;
void *check_usr_crypt(void *);
void *recv_msg(void *);
void do_crypt(SSL *client_ctx);
void accept_usr(SSL *client_ctx, struct sockaddr_in *client_addr);

void NetworkFunc(SSL_CTX *ctx) {
  server_ctx = ctx;
  int sock_stream = socket(AF_INET, SOCK_STREAM, 0);
  int sock_dgram = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock_stream == -1 || sock_dgram == -1) {
    perror("socket make fail\n");
    exit(1);
  }
  struct sockaddr_in tcp_server, udp_server;
  memset(&tcp_server.sin_zero, '\0', sizeof(tcp_server.sin_zero));
  memset(&udp_server.sin_zero, '\0', sizeof(udp_server.sin_zero));
  tcp_server.sin_addr.s_addr = htonl(INADDR_ANY);
  tcp_server.sin_port = htons(60000);
  tcp_server.sin_family = AF_INET;
  udp_server.sin_addr.s_addr = htonl(INADDR_ANY);
  udp_server.sin_port = htons(60001);
  udp_server.sin_family = AF_INET;
  if (bind(sock_stream, (struct sockaddr *)&tcp_server,
           sizeof(struct sockaddr_in)) == -1) {
    perror("tcp bind error");
    exit(1);
  }
  if (listen(sock_stream, 5) == -1) {
    perror("tcp sock listen fail");
    exit(1);
  }
  if (bind(sock_dgram, (struct sockaddr *)&udp_server,
           sizeof(struct sockaddr_in)) == -1) {
    perror("udp bind error");
    exit(1);
  }
  struct epoll_event tcp_ep, udp_ep;
  tcp_ep.data.fd = sock_stream;
  tcp_ep.events = EPOLLIN;
  udp_ep.data.fd = sock_dgram;
  udp_ep.events = EPOLLIN;
  int epfd = epoll_create1(0);
  epoll_ctl(epfd, EPOLL_CTL_ADD, sock_stream, &tcp_ep);
  epoll_ctl(epfd, EPOLL_CTL_ADD, sock_dgram, &udp_ep);
  pool_context *pool_ctx = create_pool_ctx(10);
  struct epoll_event ev[100];
  while (1) {
    int on_events = epoll_wait(epfd, ev, 100, 0);
    for (int i = 0; i < on_events; ++i) {
      if (ev[i].data.fd == sock_stream) {
        throw_work(pool_ctx, (thr_ptr_t)check_usr_crypt,
                   (void *)sock_stream); /// check user and cryption
      } else {
        throw_work(pool_ctx, (thr_ptr_t)recv_msg,
                   (void *)sock_dgram); /// msg on? or msg out
      }
    }
  }
}

/// tcp 로 들어왔으니 기존에 있는 접속을 했던 유저면 user 확인을
/// 처음 접속을 한 유저면 키 교환을
void *check_usr_crypt(void *sock_stream) {
  int sock = (int)(intptr_t)sock_stream;
  struct sockaddr_in client_addr;
  memset(&client_addr.sin_zero, '\0', 8);
  int sin_size = sizeof(struct sockaddr_in);
  int client_sock = accept(sock, (struct sockaddr *)&client_addr, &sin_size);
  if (client_sock == -1) {
    perror("client sock wrong");
    exit(1);
  }
  SSL *ssl_ctx;
  // 처음 들어왔는지 확인
  if (find_ip(client_sock, &client_addr) == -1) {
    // 처음 들어온거니 키 교환 ssl 연결로 진행
    ssl_ctx = SSL_new(server_ctx);
    SSL_set_fd(ssl_ctx, client_sock);
    do_crypt(ssl_ctx);
  } else {
    if (find_usr(client_sock, &client_addr) == -1) {
      // 무언가의 해킹일 가능성이 있음 ip 가 있는데 user 가 없다? 말이 안 됨
      close(client_sock);
      return (void *)NULL;
    }
    // 키 교환도 했고 user 도 있음 비밀번호가 맞는지 확인해야함 ssl 로 연결
    //
    ssl_ctx = SSL_new(server_ctx);
    SSL_set_fd(ssl_ctx, client_sock);
    accept_usr(ssl_ctx, &client_addr); // tcp 연결 종료
  }
  SSL_shutdown(ssl_ctx);
  SSL_free(ssl_ctx);
  close(client_sock);
  return (void *)NULL;
}

/// 기존에 접속했던 유저인지 확인 후 복호화하여 채팅방 나머지에 메시지 뿌려주기
void *recv_msg(void *sock) {}

/// 암호화 연결 및 키 교환
void do_crypt(SSL *ssl_ctx) {
  if (SSL_accept(ssl_ctx) <= 0) {
    perror("SSL accept Fail");
    exit(1);
  }
}
/// SSL 연결 후 암호화/비밀번호 확인 후
void accept_usr(SSL *ssl_ctx, struct sockaddr_in *client_addr) {}
