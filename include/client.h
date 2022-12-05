#ifndef CLIENT_H
#define CLIENT_H

#include <openssl/ssl.h>

typedef struct client {
  int fd;
  SSL *ctx;
  BIO *rbio;
  BIO *wbio;
  char* write_buf;
  size_t write_len;
  char* read_buf;
  size_t read_len;
  void (*io_on_read)(char *buf, size_t len);
} client_t;

#endif
