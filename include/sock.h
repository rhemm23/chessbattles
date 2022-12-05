#ifndef SOCK_H
#define SOCK_H

int create_tcp_socket();
void set_reuse_port(int socket);
void set_reuse_addr(int socket);
void bind_to_port(int socket, unsigned short port);
void start_listening(int socket, unsigned int backlog);
int configure_server_socket(unsigned short port, unsigned int backlog);

#endif
