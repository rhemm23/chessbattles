#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "log.h"

static void write_message(const char *type, const char *message, va_list args) {
  printf("%s: ", type);
  vfprintf(stdout, message, args);
  printf("\n");
  fflush(stdout);
}

void die(const char *error, ...) {
  va_list args;
  va_start(args, error);
  write_message("FATAL", error, args);
  va_end(args);
  exit(EXIT_FAILURE);
}

void warn(const char *warning, ...) {
  va_list args;
  va_start(args, warning);
  write_message("WARNING", warning, args);
  va_end(args);
}

void info(const char *message, ...) {
  va_list args;
  va_start(args, message);
  write_message("INFO", message, args);
  va_end(args);
}