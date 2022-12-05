#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>

#include "config.h"
#include "log.h"
#include "tls.h"

int server_fd = -1;

int open_server_socket(unsigned short port, unsigned int backlog) {

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
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    die("Could not bind socket");
  }
  if (listen(fd, backlog) < 0) {
    die("Could not listen on bound socket");
  }

  return fd;
}

void interrupt_handler(int signal) {
  info("Received interrupt, shutting down server");
  exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {

  config_t config;
  load_config(argc, argv, &config);
  int use_tls = (config.cert_file != NULL && config.key_file != NULL);

  // Setup interrupt handler, ignore broken pipe
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, interrupt_handler);

  // Load SSL context
  SSL_CTX *ssl_context = NULL;
  if (use_tls) {
    ssl_context = init_server_ssl_context(config.cert_file, config.key_file);
    info("Successfully initialized TLS context");
  } else {
    info("No certificate specified, skipping TLS setup");
  }

  // Open server socket
  server_fd = open_server_socket(config.port, config.backlog);
  info("Successfully created socket bound to port %hu", config.port);

  while (1) {
    int client;
    SSL *ssl;
    socklen_t client_addr_len;
    struct sockaddr client_addr;
    if ((client = accept(server_fd, &client_addr, &client_addr_len)) < 0) {
      warn("Failed to accept incoming client");
    } else {
      char *data = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\nHi!";
      int len = strlen(data);
      if (use_tls) {
        ssl = SSL_new(ssl_context);
        SSL_set_fd(ssl, client);
        if (SSL_accept(ssl) < 1) {
          warn("Failed to accept client with TLS");
        } else {
          SSL_write(ssl, data, len);
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
      } else {
        write(client, data, len);
      }
      close(client);
    }
  }

  // Graceful cleanup
  close(server_fd);
  if (use_tls) {
    SSL_CTX_free(ssl_context);
  }

  return EXIT_SUCCESS;
}
