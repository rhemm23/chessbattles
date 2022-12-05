#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

short PORT = 80;
int BACKLOG = 64;

static void die(const char *error) {
  printf("FATAL: %s\n", error);
  exit(EXIT_FAILURE);
}

static void warn(const char *warning) {
  printf("WARNING: %s\n", warning);
}

static void info(const char *message) {
  printf("INFO: %s\n", message);
}

int main() {

  // Create socket
  int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd == -1) {
    die("Could not open socket");
  }
  
  // Configure socket
  const int enable = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0) {
    die("Could not set reuse port option on socket");
  }
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
    die("Could not set reuse address option on socket");
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_len = sizeof(addr);
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(PORT);

  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    die("Could not bind socket");
  }
  if (listen(fd, BACKLOG) < 0) {
    die("Could not listen on bound socket");
  }

  info("Successfully started service");

  while (1) {
    int client;
    socklen_t client_addr_len;
    struct sockaddr client_addr;
    if ((client = accept(fd, &client_addr, &client_addr_len)) < 0) {
      warn("Failed to accept incoming client");
    } else {
      char *data = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\nHi!";
      write(client, data, strlen(data));
      shutdown(client, SHUT_RDWR);
      close(client);
    }
  }

  return EXIT_SUCCESS;
}
