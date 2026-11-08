/**
 * \file log.h
 * \brief Logging declarations for libmountsandbox.
 */
#ifndef LIBMOUNTSANDBOX_LOG_H
#define LIBMOUNTSANDBOX_LOG_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* clang-format off */
#include "sandbox.h"
#include <stdio.h>
#include <stdarg.h>
/* clang-format on */

/**
 * @brief Outputs a formatted debug log message to stderr.
 * @param fmt Printf-style format string.
 * @return SANDBOX_SUCCESS on success, or SANDBOX_ERR_INVALID_ARG if fmt is
 * NULL.
 */
NO_DISCARD sandbox_error_t libmountsandbox_log_debug(const char *fmt, ...);

#ifndef LOG_DEBUG
/** \brief Macro to log debug messages via libmountsandbox_log_debug. */
#define LOG_DEBUG libmountsandbox_log_debug
#endif /* !LOG_DEBUG */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LIBMOUNTSANDBOX_LOG_H */
