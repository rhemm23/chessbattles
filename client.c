#include <openssl/ssl.h>
#include <stdbool.h>
#include <string.h>

#include "client.h"
#include "tls.h"

static bool move_available_bytes_to_output(client_t *client) {
  int n;
  do {
    char buf[256];
    n = BIO_read(client->wbio, buf, sizeof(buf));
    if (n > 0) {
      enqueue_unencrypted_data(client, buf, n);
    } else if (!BIO_should_retry(client->wbio)) {
      return false;
    }
  } while (n > 0);
  return true;
}

bool process_client_bytes(client_t *client, char *src, size_t len) {
  char buf[256];
  while (len > 0) {
    int n = BIO_write(client->rbio, src, len);
    if (n <= 0) {
      return false;
    }

    src += n;
    len -= n;

    if (!SSL_is_init_finished(client->ctx)) {
      switch (SSL_get_error(client->ctx, SSL_accept(client->ctx))) {
        case SSL_ERROR_WANT_WRITE:
        case SSL_ERROR_WANT_READ:
          if (!move_available_bytes_to_output(client)) {
            return false;
          }
          break;

        case SSL_ERROR_NONE:
          if (!SSL_is_init_finished(client->ctx)) {
            return true;
          }
          break;

        default:
          return false;
      }
    }

    // Init is done
    do {
      n = SSL_read(client->ctx, buf, sizeof(buf));
      if (n > 0) {
        client->io_on_read(buf, n);
      }
    } while (n > 0);

    // Check for potential error
    int error = SSL_get_error(client->ctx, n);
    if (error == SSL_ERROR_WANT_WRITE || error == SSL_ERROR_WANT_READ) {
      if (!move_available_bytes_to_output(client)) {
        return false;
      }
    } else if (error != SSL_ERROR_NONE) {
      return false;
    }
  }
}

void enqueue_unencrypted_data(client_t *client, char *src, size_t len) {
  client->write_buf = (char*)realloc(client->write_buf, client->write_len + len);
  memcpy(client->write_buf + client->write_len, src, len);
  client->write_len += len;
}

bool initialize_client(client_t *client, int fd) {

  client->fd = fd;
  client->ctx = move_client_to_ssl(fd);
  
  if (client->ctx == NULL) {
    return false;
  }

  client->rbio = BIO_new(BIO_s_mem());
  client->wbio = BIO_new(BIO_s_mem());

  SSL_set_accept_state(client->ctx);
  SSL_set_bio(client->ctx, client->rbio, client->wbio);

  client->read_len = 0;
  client->write_len = 0;

  client->read_buf = NULL;
  client->write_buf = NULL;

  return true;
}