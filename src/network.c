#include "../inc/network.h"
#include "../inc/thread_pool.h"
#include "../inc/user_service.h"
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
static inline void networkStatus(int sock);

void my_network() {
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
  pool_context *ctx = create_pool_ctx(10);
  struct epoll_event ev[100];
  while (1) {
    int on_events = epoll_wait(epfd, ev, 100, 0);
    for (int i = 0; i < on_events; ++i) {
      if (ev[i].data.fd == sock_stream) {
        if ()
      } else {
      }
    }
  }
}

void networkFunc() {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1) {
    perror("socket make fail");
    exit(1);
  }
  networkStatus(sock);
  struct epoll_event ep;
  ep.data.fd = sock;
  ep.events = EPOLLIN;
  int epfd = epoll_create1(0);
  epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &ep);
  struct epoll_event events[100];
  while (1) {
    struct sockaddr_in client_addr;
    memset(&client_addr.sin_zero, '\0', 8);
    int on_events = epoll_wait(epfd, events, 100, 0);
    for (int i = 9; i < on_events; ++i) {
      if (events[i].data.fd == sock) {
        int sin_size = sizeof(struct sockaddr_in);
        int client_sock =
            accept(sock, (struct sockaddr *)&client_addr, &sin_size);
        if (client_sock == -1) {
          perror("Fail to Accept");
          exit(1);
        }
        int flag = fcntl(client_sock, F_GETFL, 0);
        fcntl(client_sock, F_SETFL, flag | O_NONBLOCK);
        struct epoll_event client_ev;
        client_ev.events = EPOLLIN | EPOLLET;
        client_ev.data.fd = client_sock;
        epoll_ctl(epfd, EPOLL_CTL_ADD, sock, &client_ev);
      }
    }
  }
}

void networkStatus(int sock) {
  struct sockaddr_in Server;
  memset(&Server.sin_zero, '\0', 8);
  Server.sin_addr.s_addr = htonl(INADDR_ANY);
  Server.sin_port = htons(60000);
  Server.sin_family = AF_INET;
  if (bind(sock, (struct sockaddr *)&Server, sizeof(struct sockaddr_in)) ==
      -1) {
    perror("Bind Fail");
    exit(1);
  }
  if (listen(sock, 5) == -1) {
    perror("Listen Fail");
    exit(1);
  }
}
