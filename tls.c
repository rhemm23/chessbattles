#include "tls.h"
#include "log.h"

SSL_CTX * init_server_ssl_context(char *cert_file, char *key_file) {

  uint64_t options =
    OPENSSL_INIT_ADD_ALL_DIGESTS |
    OPENSSL_INIT_ADD_ALL_CIPHERS |
    OPENSSL_INIT_LOAD_SSL_STRINGS |
    OPENSSL_INIT_LOAD_CRYPTO_STRINGS;

  if (OPENSSL_init_ssl(options, NULL) < 0) {
    die("Could not initialize OpenSSL library");
  }

  const SSL_METHOD *method = TLS_server_method();
  SSL_CTX *context = SSL_CTX_new(method);

  if (context == NULL) {
    die("Could not load TLS context");
  }
  if (SSL_CTX_use_certificate_file(context, cert_file, SSL_FILETYPE_PEM) < 1) {
    die("Could not load server certificate");
  }
  if (SSL_CTX_use_PrivateKey_file(context, key_file, SSL_FILETYPE_PEM) < 1) {
    die("Could not load server certificate private key");
  }
  if (!SSL_CTX_check_private_key(context)) {
    die("Private key does not match with corresponding certificate");
  }

  return context;
}
