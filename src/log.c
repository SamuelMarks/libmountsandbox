/**
 * \file log.c
 * \brief Logging implementation for libmountsandbox.
 */
/* clang-format off */
#include "log.h"
#include <stdio.h>
#include <stdarg.h>
/* clang-format on */

#if defined(SANDBOX_ENABLE_MOCKS)
/** @brief Flag to force libmountsandbox_log_debug to fail during fault
 * injection. */
int g_sandbox_mock_log_fail = 0;
#endif

/**
 * @brief Internal function to output debug logs.
 * @param fmt Printf-style format string.
 * @return SANDBOX_SUCCESS on success, or SANDBOX_ERR_INVALID_ARG if fmt is
 * NULL.
 */
sandbox_error_t libmountsandbox_log_debug(const char *fmt, ...) {
  va_list args;
  char nl[2];
  if (!fmt) {
    return SANDBOX_ERR_INVALID_ARG;
  }
#if defined(SANDBOX_ENABLE_MOCKS)
  if (g_sandbox_mock_log_fail) {
    return SANDBOX_ERR_IO;
  }
#endif
  nl[0] = 10;
  nl[1] = 0;
  va_start(args, fmt);
#if defined(_MSC_VER)
  vfprintf_s(stderr, fmt, args);
#else
  vfprintf(stderr, fmt, args);
#endif
  fputs(nl, stderr);
  va_end(args);
  return SANDBOX_SUCCESS;
}
