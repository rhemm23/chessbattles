#include <signal.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>

#include "config.h"
#include "sock.h"
#include "log.h"
#include "tls.h"

int server_fd = -1;
volatile bool terminate = false;

static void cleanup() {
  close_server_ssl_context();
  close(server_fd);
}

void interrupt_handler(int signal) {
  info("Received interrupt, shutting down server");
  terminate = true;
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

  int nfds = 1;
  SSL *client_ctxs[256];
  struct pollfd fds[256];
  memset(fds, 0, sizeof(fds));

  fds[0].fd = server_fd;
  fds[0].events = POLL_IN;

  while (!terminate) {
    int rc = poll(fds, nfds, 1000);
    if (rc < 0) {
      die("Call to poll failed");
    } else if (rc > 0) {
      int current_size = nfds;
      bool dropped_connections = false;
      for (int i = 0; i < current_size; i++) {
        if (fds[i].revents == POLL_IN) {
          if (fds[i].fd == server_fd) {
            int client;
            do {
              client = accept(server_fd, NULL, NULL);
              if (client < 0 && errno != EWOULDBLOCK) {
                die("Incoming connection could not be accepted");
              } else if (client >= 0) {
                SSL *client_ctx = move_client_to_ssl(client);
                if (client_ctx == NULL) {
                  close(client);
                  warn("TLS handshake failed");
                } else {
                  fds[nfds].fd = client;
                  fds[nfds].revents = POLL_IN;
                  nfds++;
                }
              }
            } while (client >= 0);
          } else {
            do {
              char buffer[1024];
              int nbytes = recv(fds[i].fd, buffer, 1024, 0);
              if (nbytes < 0 && errno != EWOULDBLOCK) {
                die("Receive method call failed");
              } else if (nbytes > 0) {
                write(STDOUT_FILENO, buffer, nbytes);
              } else if (nbytes == 0) {
                close(fds[i].fd);
                fds[i].fd = -1;
                dropped_connections = true;
              } else {
                break;
              }
            } while (true);
          }
        }
      }
      if (dropped_connections) {
        for (int i = 0; i < nfds; i++) {
          if (fds[i].fd == -1) {
            for (int j = i; j < nfds - 1; j++) {
              fds[j].fd = fds[j + 1].fd;
              fds[j].events = fds[j + 1].events;
            }
            i--;
            nfds--;
          }
        }
      }
    }

    // int client;
    // socklen_t client_addr_len;
    // struct sockaddr client_addr;
    // if ((client = accept(server_fd, &client_addr, &client_addr_len)) < 0) {
    //   warn("Failed to accept incoming client");
    // } else {
    //   char *data = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\nHi!";
    //   int len = strlen(data);
    //   if (use_tls) {
    //     SSL *ssl = move_client_to_ssl(client);
    //     if (ssl == NULL) {
    //       warn("Failed to accept client with TLS");
    //     } else {
    //       SSL_write(ssl, data, len);
    //       SSL_shutdown(ssl);
    //       SSL_free(ssl);
    //     }
    //   } else {
    //     write(client, data, len);
    //   }
    //   close(client);
    // }
  }

  // Clean up client sockets
  for (int i = 0; i < nfds; i++) {
    if (fds[i].fd >= 0) {
      close(fds[i].fd);
    }
  }

  // Clean up server
  cleanup();

  return EXIT_SUCCESS;
}
