/**
 * @file sandbox_common.h
 * @brief Shared internal execution, stream buffer, and fault-injection helpers.
 */
#ifndef LIBMOUNTSANDBOX_COMMON_H
#define LIBMOUNTSANDBOX_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* clang-format off */
#include "sandbox.h"
#include <stdio.h>
#include <stdlib.h>
/* clang-format on */

#if defined(_MSC_VER)
/** @brief Portable format specifier for unsigned long values. */
#define SANDBOX_ULONG_FMT "%lu"
/** @brief Portable format specifier for unsigned int values. */
#define SANDBOX_UINT_FMT "%u"
/** @brief Portable format specifier for signed int values. */
#define SANDBOX_INT_FMT "%d"
#else
/** @brief Portable format specifier for unsigned long values. */
#define SANDBOX_ULONG_FMT "%lu"
/** @brief Portable format specifier for unsigned int values. */
#define SANDBOX_UINT_FMT "%u"
/** @brief Portable format specifier for signed int values. */
#define SANDBOX_INT_FMT "%d"
#endif

/**
 * @brief Represents computed Windows Job Object limit flags and quotas.
 */
typedef struct {
  /** @brief Bitmask of active Job Object limit flags. */
  unsigned long limit_flags;
  /** @brief Maximum active processes allowed in the job. */
  unsigned int active_process_limit;
  /** @brief Process virtual memory limit in bytes (0 if unlimited). */
  unsigned long process_memory_bytes;
  /** @brief CPU rate control weight/percentage (1-100, or 0 if unlimited). */
  unsigned int cpu_rate_percent;
} sandbox_job_limits_t;

/**
 * @brief Allocates heap memory (or fails under fault-injection when mocks are
 * enabled).
 * @param size Number of bytes to allocate.
 * @param out_ptr Pointer to receive the allocated memory block.
 * @return SANDBOX_SUCCESS on success, or an error enum on failure.
 */
sandbox_error_t sandbox_alloc(size_t size, void **out_ptr);

/**
 * @brief Opens a temporary file using standard or MSVC Safe CRT routines.
 * @param out_fp Pointer to receive the opened FILE pointer.
 * @return SANDBOX_SUCCESS on success, or SANDBOX_ERR_IO on failure.
 */
sandbox_error_t sandbox_open_tmpfile(FILE **out_fp);

/**
 * @brief Reads all content from a temporary file stream into a dynamically
 * allocated buffer.
 * @param fp The file stream to read from.
 * @param buf Pointer to receive the allocated null-terminated buffer.
 * @param size Optional pointer to receive the number of bytes read.
 * @return SANDBOX_SUCCESS on success, or an error enum on failure.
 */
sandbox_error_t sandbox_read_fp_to_buffer(FILE *fp, char **buf, size_t *size);

/**
 * @brief Escapes double quotes and backslashes in a filesystem path for safe
 * inclusion in a macOS Seatbelt Profile Language (SBPL) string literal.
 * @param raw_path The unescaped host directory path.
 * @param out_escaped Pointer to receive the newly allocated escaped string.
 * @return SANDBOX_SUCCESS on success, or an error enum on failure.
 */
sandbox_error_t sandbox_escape_sbpl_path(const char *raw_path,
                                         char **out_escaped);

/**
 * @brief Computes Windows Job Object limit parameters from a sandbox_config_t.
 * @param config The sandbox configuration parameters.
 * @param out_limits Pointer to store the computed Job Object limits.
 * @return SANDBOX_SUCCESS on success, or SANDBOX_ERR_INVALID_ARG if NULL.
 */
sandbox_error_t sandbox_configure_job_limits(const sandbox_config_t *config,
                                             sandbox_job_limits_t *out_limits);

/**
 * @brief Spawns an external binary with arguments, optional stream redirection,
 * and timeout enforcement.
 * @param bin_name Name of the executable to invoke in PATH.
 * @param exec_argv Null-terminated argument vector.
 * @param config Sandbox configuration parameters.
 * @param out_fp Optional temporary file stream for capturing stdout.
 * @param err_fp Optional temporary file stream for capturing stderr.
 * @param exit_status Pointer to receive the process exit status.
 * @return SANDBOX_SUCCESS on success, or an error enum on failure.
 */
sandbox_error_t sandbox_spawn_and_wait(const char *bin_name, char **exec_argv,
                                       const sandbox_config_t *config,
                                       FILE *out_fp, FILE *err_fp,
                                       int *exit_status);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LIBMOUNTSANDBOX_COMMON_H */
