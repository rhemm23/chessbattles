#ifndef LOG_H
#define LOG_H

#include <stdarg.h>

void die(const char *error, ...);
void info(const char *message, ...);
void warn(const char *warning, ...);

#endif
