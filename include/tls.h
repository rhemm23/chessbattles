#ifndef TLS_H
#define TLS_H

#include <openssl/ssl.h>

void close_server_ssl_context();
SSL * move_client_to_ssl(int client_socket);
void init_server_ssl_context(char *cert_file, char *key_file);

#endif
