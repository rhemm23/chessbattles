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
#include "sock.h"
#include "log.h"
#include "tls.h"

int server_fd = -1;

static void cleanup() {
  close_server_ssl_context();
  close(server_fd);
}

void interrupt_handler(int signal) {
  info("Received interrupt, shutting down server");
  cleanup();
  exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {

  config_t config;
  load_config(argc, argv, &config);
  int use_tls = (config.cert_file != NULL && config.key_file != NULL);

  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, interrupt_handler);

  if (use_tls) {
    init_server_ssl_context(config.cert_file, config.key_file);
    info("Successfully initialized TLS context");
  } else {
    info("No certificate specified, skipping TLS setup");
  }

  server_fd = configure_server_socket(config.port, config.backlog);
  info("Successfully created socket bound to port %hu", config.port);

  while (1) {
    int client;
    socklen_t client_addr_len;
    struct sockaddr client_addr;
    if ((client = accept(server_fd, &client_addr, &client_addr_len)) < 0) {
      warn("Failed to accept incoming client");
    } else {
      char *data = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\nHi!";
      int len = strlen(data);
      if (use_tls) {
        SSL *ssl = move_client_to_ssl(client);
        if (ssl == NULL) {
          warn("Failed to accept client with TLS");
        } else {
          SSL_write(ssl, data, len);
          SSL_shutdown(ssl);
          SSL_free(ssl);
        }
      } else {
        write(client, data, len);
      }
      close(client);
    }
  }

  cleanup();
  return EXIT_SUCCESS;
}
