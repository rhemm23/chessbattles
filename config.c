#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "config.h"

static void show_usage_and_quit() {
  printf("\nAllowed arguments:\n\n\t-c [cert file] - Specify the server certificate file path\n\t-k [key file]  - Specify the server private key file path\n\t-p [port]    - Specify the server port\n\t-b [backlog] - Specify the maximum connection backlog allowed\n\n");
  exit(EXIT_FAILURE);
}

void load_config(int argc, char **argv, config_t *config) {

  // Default values
  config->cert_file = NULL;
  config->key_file = NULL;
  config->backlog = 32;
  config->port = 80;

  for (int i = 1; i < argc; i++) {
    if (argv[i][0] == '-' && strlen(argv[i]) == 2) {
      if ((i + 1) == argc) {
        show_usage_and_quit();
      }

      char *parse_end;
      long numeric_value;

      switch (argv[i][1]) {
        case 'c':
          config->cert_file = argv[++i];
          break;

        case 'k':
          config->key_file = argv[++i];
          break;
        
        case 'p':
          numeric_value = strtol(argv[++i], &parse_end, 10);
          if (*parse_end != '\0' || numeric_value < 0 || numeric_value > 65535) {
            show_usage_and_quit();
          } else {
            config->port = (unsigned short)numeric_value;
          }
          break;

        case 'b':
          numeric_value = strtol(argv[++i], &parse_end, 10);
          if (*parse_end != '\0' || numeric_value < 0 || numeric_value > 4294967295L) {
            show_usage_and_quit();
          } else {
            config->backlog = (unsigned int)numeric_value;
          }
          break;

        default:
          show_usage_and_quit();
      }
    }
  }

  if ((config->cert_file == NULL && config->key_file != NULL) || (config->cert_file != NULL && config->key_file == NULL)) {
    printf("\nOne of the server certificate file or private key file was specified, but the other was not. \nSpecify both to use TLS, or neither to ignore TLS\n\n");
    exit(EXIT_FAILURE);
  }
}
