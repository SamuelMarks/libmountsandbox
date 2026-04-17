/**
 * \file log.h
 * \brief Logging macros for libmountsandbox.
 */
#ifndef LIBMOUNTSANDBOX_LOG_H
#define LIBMOUNTSANDBOX_LOG_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* clang-format off */
#include <stdio.h>
#include <stdarg.h>
/* clang-format on */

#ifndef LOG_DEBUG
#ifdef DEBUG
void libmountsandbox_log_debug(const char *fmt, ...);
#define LOG_DEBUG libmountsandbox_log_debug
#else
void libmountsandbox_log_debug(const char *fmt, ...);
#define LOG_DEBUG 1 ? (void)0 : libmountsandbox_log_debug
#endif /* DEBUG */
#endif /* !LOG_DEBUG */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LIBMOUNTSANDBOX_LOG_H */
