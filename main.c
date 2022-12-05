#include <signal.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

short PORT = 443;
int BACKLOG = 64;

const char *CERTIFICATE_FILE = "/etc/letsencrypt/live/chessbattles.net/cert.pem";
const char *KEY_FILE = "/etc/letsencrypt/live/chessbattles.net/privkey.pem";

volatile int terminated = 0;

static void die(const char *error) {
  printf("FATAL: %s\n", error);
  fflush(stdout);
  exit(EXIT_FAILURE);
}

static void warn(const char *warning) {
  printf("WARNING: %s\n", warning);
  fflush(stdout);
}

static void info(const char *message) {
  printf("INFO: %s\n", message);
  fflush(stdout);
}

SSL_CTX * init_server_tls() {

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
  if (SSL_CTX_use_certificate_file(context, CERTIFICATE_FILE, SSL_FILETYPE_PEM) < 1) {
    die("Could not load server certificate");
  }
  if (SSL_CTX_use_PrivateKey_file(context, KEY_FILE, SSL_FILETYPE_PEM) < 1) {
    die("Could not load server certificate private key");
  }
  if (!SSL_CTX_check_private_key(context)) {
    die("Private key does not match with corresponding certificate");
  }

  return context;
}

int open_server_socket() {

  // Create socket
  int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd == -1) {
    die("Could not open socket");
  }
  
  // Configure socket
  const int enable = 1;
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(int)) < 0) {
    die("Could not set reuse port option on socket");
  }
  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
    die("Could not set reuse address option on socket");
  }

  struct sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(PORT);

  if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    die("Could not bind socket");
  }
  if (listen(fd, BACKLOG) < 0) {
    die("Could not listen on bound socket");
  }

  return fd;
}

void interrupt_handler(int signal) {
  info("Received interrupt, shutting down server");
  exit(EXIT_SUCCESS);
}

void show_usage_and_quit() {
  printf("\nAllowed arguments:\n\n\t-c [cert file] - Specify the server certificate file path\n\t-k [key file]  - Specify the server private key file path\n\t-p [port]    - Specify the server port\n\t-b [backlog] - Specify the maximum connection backlog allowed\n\n");
  exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {

  char *cert_file = NULL;
  char *key_file = NULL;

  unsigned int backlog = 32;
  unsigned short port = 80;

  // Parse command line arguments
  for (int i = 1; i < argc; i++) {
    if (argv[i][0] == '-' && strlen(argv[i]) == 2) {

      // Assure value follows
      if ((i + 1) == argc) {
        show_usage_and_quit();
      }

      char *parse_end;
      long numeric_value;

      // Determine which command
      switch (argv[i][1]) {
        case 'c':
          cert_file = argv[++i];
          break;

        case 'k':
          key_file = argv[++i];
          break;
        
        case 'p':
          numeric_value = strtol(argv[++i], &parse_end, 10);
          if (*parse_end != '\0' || numeric_value < 0 || numeric_value > 65535) {
            show_usage_and_quit();
          } else {
            port = (unsigned short)numeric_value;
          }
          break;

        case 'b':
          numeric_value = strtol(argv[++i], &parse_end, 10);
          if (*parse_end != '\0' || numeric_value < 0 || numeric_value > 4294967295L) {
            show_usage_and_quit();
          } else {
            backlog = (unsigned int)numeric_value;
          }
          break;

        default:
          show_usage_and_quit();
      }
    }
  }

  if ((cert_file == NULL && key_file != NULL) || (cert_file != NULL && key_file == NULL)) {
    printf("\nOne of the server certificate file or private key file was specified, but the other was not. \nSpecify both to use TLS, or neither to ignore TLS\n\n");
    exit(EXIT_FAILURE);
  }

  int use_tls = (cert_file != NULL && key_file != NULL);

  // Setup interrupt handler, ignore broken pipe
  signal(SIGPIPE, SIG_IGN);
  signal(SIGINT, interrupt_handler);

  // Load SSL context
  SSL_CTX *ssl_context = NULL;
  if (use_tls) {
    ssl_context = init_server_tls();
    info("Successfully initialized TLS context");
  } else {
    info("No certificate specified, skipping TLS setup");
  }

  // Open server socket
  int fd = open_server_socket();
  info("Successfully opened server socket");

  while (!terminated) {
    int client;
    SSL *ssl;
    socklen_t client_addr_len;
    struct sockaddr client_addr;
    if ((client = accept(fd, &client_addr, &client_addr_len)) < 0) {
      warn("Failed to accept incoming client");
    } else {
      char *data = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 3\r\n\r\nHi!";
      int len = strlen(data);
      if (use_tls) {
        ssl = SSL_new(ssl_context);
        SSL_set_fd(ssl, client);
        if (SSL_accept(ssl) < 1) {
          warn("Failed to accept client with TLS");
        } else {
          SSL_write(ssl, data, len);
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
      } else {
        write(client, data, len);
      }
      close(client);
    }
  }

  // Graceful cleanup
  close(fd);
  if (use_tls) {
    SSL_CTX_free(ssl_context);
  }

  return EXIT_SUCCESS;
}
