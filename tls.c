#include "tls.h"
#include "log.h"

SSL_CTX *server_ssl_context = NULL;

SSL * move_client_to_ssl(int client_socket) {

  SSL *ssl = SSL_new(server_ssl_context);
  SSL_set_fd(ssl, client_socket);

  if (SSL_accept(ssl) <= 0) {
    SSL_free(ssl);
    return NULL;
  }

  return ssl;
}

void close_server_ssl_context() {
  SSL_CTX_free(server_ssl_context);
}

void init_server_ssl_context(char *cert_file, char *key_file) {

  uint64_t options =
    OPENSSL_INIT_ADD_ALL_DIGESTS |
    OPENSSL_INIT_ADD_ALL_CIPHERS |
    OPENSSL_INIT_LOAD_SSL_STRINGS |
    OPENSSL_INIT_LOAD_CRYPTO_STRINGS;

  if (OPENSSL_init_ssl(options, NULL) < 0) {
    die("Could not initialize OpenSSL library");
  }

  const SSL_METHOD *method = TLS_server_method();
  server_ssl_context = SSL_CTX_new(method);

  if (server_ssl_context == NULL) {
    die("Could not load TLS context");
  }
  if (SSL_CTX_use_certificate_file(server_ssl_context, cert_file, SSL_FILETYPE_PEM) < 1) {
    die("Could not load server certificate");
  }
  if (SSL_CTX_use_PrivateKey_file(server_ssl_context, key_file, SSL_FILETYPE_PEM) < 1) {
    die("Could not load server certificate private key");
  }
  if (!SSL_CTX_check_private_key(server_ssl_context)) {
    die("Private key does not match with corresponding certificate");
  }
}
