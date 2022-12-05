#ifndef CONFIG_H
#define CONFIG_H

typedef struct config {
  unsigned short port;
  unsigned int backlog;
  char *cert_file;
  char *key_file;
} config_t;

void load_config(int argc, char **argv, config_t *config);

#endif
