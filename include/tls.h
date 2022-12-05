#ifndef TLS_H
#define TLS_H

#include <openssl/ssl.h>

SSL_CTX * init_server_ssl_context(char *cert_file, char *key_file);

#endif
