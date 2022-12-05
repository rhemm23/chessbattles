#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>

#include "sock.h"
#include "log.h"

void set_reuse_port(int socket) {
  const int enable = 1;
  if (setsockopt(socket, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0) {
    die("Could not set socket to reuse port");
  }
}

void set_reuse_addr(int socket) {
  const int enable = 1;
  if (setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
    die("Could not set socket to reuse address");
  }
}

int create_tcp_socket() {
  int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock < 0) {
    die("Could not create socket");
  }
  return sock;
}

void bind_to_port(int socket, unsigned short port) {

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    die("Could not bind socket to port %hu", port);
  }
}

void start_listening(int socket, unsigned int backlog) {
  if (listen(socket, backlog) < 0) {
    die("Could not set socket to a listening state");
  }
}

void set_socket_nonblocking(int socket) {
  int flags = fcntl(socket, F_GETFL);
  if (fcntl(socket, F_SETFL, flags | O_NONBLOCK) < 0) {
    die("Could not set socket to be non-blocking");
  }
}

int configure_server_socket(unsigned short port, unsigned int backlog) {
  int server_fd = create_tcp_socket();
  set_socket_nonblocking(server_fd);
  set_reuse_port(server_fd);
  set_reuse_addr(server_fd);
  bind_to_port(server_fd, port);
  start_listening(server_fd, backlog);
  return server_fd;
}
