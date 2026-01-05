#include "../inc/network.h"
#include <sys/epoll.h>

static inline void networkStatus(int sock);

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
