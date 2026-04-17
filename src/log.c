/**
 * \file log.c
 * \brief Logging implementation for libmountsandbox.
 */
/* clang-format off */
#include "log.h"
#include <stdio.h>
#include <stdarg.h>
/* clang-format on */

/**
 * \brief Internal function to output debug logs.
 * \param fmt Format string.
 */
void libmountsandbox_log_debug(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  fprintf(stderr, "\n");
  va_end(args);
}
