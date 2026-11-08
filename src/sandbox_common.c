#if defined(__APPLE__) || defined(__linux__) || defined(__CYGWIN__)
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif
#endif
/**
 * @file sandbox_common.c
 * @brief Implementation of shared execution and stream helpers.
 */
/* clang-format off */
#include "sandbox_common.h"
#include "log.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(__WATCOMC__)
#include <io.h>
#include <process.h>
#ifdef _WIN32
#include <winsock2.h>
#endif
#else
#include <signal.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
/* clang-format on */

#if defined(_MSC_VER)
/** @brief Platform spawnvp wrapper for MSVC. */
#define PLATFORM_SPAWNVP _spawnvp
/** @brief Platform synchronous spawn mode for MSVC. */
#define PLATFORM_P_WAIT _P_WAIT
/** @brief Platform asynchronous spawn mode for MSVC. */
#define PLATFORM_P_NOWAIT _P_NOWAIT
#else
/** @brief Platform spawnvp wrapper for non-MSVC Windows compilers. */
#define PLATFORM_SPAWNVP spawnvp
/** @brief Platform synchronous spawn mode for non-MSVC Windows compilers. */
#define PLATFORM_P_WAIT P_WAIT
/** @brief Platform asynchronous spawn mode for non-MSVC Windows compilers. */
#define PLATFORM_P_NOWAIT P_NOWAIT
#endif

/** @brief Windows Job Object limit flag: active process count limit. */
#define SANDBOX_JOB_LIMIT_ACTIVE_PROCESS 0x00000008UL
/** @brief Windows Job Object limit flag: per-process memory limit. */
#define SANDBOX_JOB_LIMIT_PROCESS_MEMORY 0x00000100UL
/** @brief Windows Job Object limit flag: terminate on unhandled exception. */
#define SANDBOX_JOB_LIMIT_DIE_ON_UNHANDLED_EXCEPTION 0x00000400UL
/** @brief Windows Job Object limit flag: kill all processes on job close. */
#define SANDBOX_JOB_LIMIT_KILL_ON_JOB_CLOSE 0x00002000UL

#if defined(SANDBOX_ENABLE_MOCKS)
/** @brief Countdown until malloc fails (1 = fail on next call, 0 = disabled).
 */
int g_sandbox_mock_malloc_countdown = 0;
/** @brief Countdown until tmpfile fails (1 = fail on next call, 0 = disabled).
 */
int g_sandbox_mock_tmpfile_countdown = 0;
/** @brief Simulated spawn behavior (0 = real, 1 = fail, 2 = timeout, 3 = exit
 * 0, 4 = exit 42, 5 = negative exit). */
int g_sandbox_mock_spawn_mode = 0;
/** @brief Flag to force ftell to return -1 in sandbox_read_fp_to_buffer. */
int g_sandbox_mock_ftell_neg = 0;
/** @brief Flag to force fseek to fail in sandbox_read_fp_to_buffer. */
int g_sandbox_mock_fseek_fail = 0;
#endif

/**
 * @brief Allocates heap memory (or fails under fault-injection when mocks are
 * enabled).
 * @param size Number of bytes to allocate.
 * @param out_ptr Pointer to receive the allocated memory block.
 * @return SANDBOX_SUCCESS on success, or an error enum on failure.
 */
sandbox_error_t sandbox_alloc(size_t size, void **out_ptr) {
  void *p = NULL;
  if (!out_ptr) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  *out_ptr = NULL;
#if defined(SANDBOX_ENABLE_MOCKS)
  if (g_sandbox_mock_malloc_countdown > 0) {
    g_sandbox_mock_malloc_countdown--;
    if (g_sandbox_mock_malloc_countdown == 0) {
      return SANDBOX_ERR_OUT_OF_MEMORY;
    }
  }
  p = malloc(size);
#else
  p = malloc(size);
  if (!p) {
    return SANDBOX_ERR_OUT_OF_MEMORY;
  }
#endif
  *out_ptr = p;
  return SANDBOX_SUCCESS;
}

/**
 * @brief Opens a temporary file using standard or MSVC Safe CRT routines.
 * @param out_fp Pointer to receive the opened FILE pointer.
 * @return SANDBOX_SUCCESS on success, or SANDBOX_ERR_IO on failure.
 */
sandbox_error_t sandbox_open_tmpfile(FILE **out_fp) {
  if (!out_fp) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  *out_fp = NULL;
#if defined(SANDBOX_ENABLE_MOCKS)
  if (g_sandbox_mock_tmpfile_countdown > 0) {
    g_sandbox_mock_tmpfile_countdown--;
    if (g_sandbox_mock_tmpfile_countdown == 0) {
      return SANDBOX_ERR_IO;
    }
  }
#endif
#if defined(_MSC_VER)
  if (tmpfile_s(out_fp) != 0 || !*out_fp) {
    *out_fp = NULL;
    return SANDBOX_ERR_IO;
  }
#else
  *out_fp = tmpfile();
#if !defined(SANDBOX_ENABLE_MOCKS)
  if (!*out_fp) {
    return SANDBOX_ERR_IO;
  }
#endif
#endif
  return SANDBOX_SUCCESS;
}

/**
 * @brief Reads all content from a temporary file stream into a dynamically
 * allocated buffer.
 * @param fp The file stream to read from.
 * @param buf Pointer to receive the allocated null-terminated buffer.
 * @param size Optional pointer to receive the number of bytes read.
 * @return SANDBOX_SUCCESS on success, or an error enum on failure.
 */
sandbox_error_t sandbox_read_fp_to_buffer(FILE *fp, char **buf, size_t *size) {
  sandbox_error_t rc;
  long fsize;
  size_t read_bytes;
  void *raw_buf = NULL;
  if (!fp || !buf) {
    return SANDBOX_ERR_INVALID_ARG;
  }
#if defined(SANDBOX_ENABLE_MOCKS)
  if (g_sandbox_mock_fseek_fail) {
    return SANDBOX_ERR_IO;
  }
#endif
  fseek(fp, 0, SEEK_END);
  fsize = ftell(fp);
#if defined(SANDBOX_ENABLE_MOCKS)
  if (g_sandbox_mock_ftell_neg) {
    fsize = -1L;
  }
#endif
  rewind(fp);
  if (fsize < 0) {
    fsize = 0;
  }
  rc = sandbox_alloc((size_t)fsize + 1, &raw_buf);
  if (rc != SANDBOX_SUCCESS) {
    *buf = NULL;
    if (size) {
      *size = 0;
    }
    return rc;
  }
  *buf = (char *)raw_buf;
  read_bytes = fread(*buf, 1, (size_t)fsize, fp);
  (*buf)[read_bytes] = 0;
  if (size) {
    *size = read_bytes;
  }
  return SANDBOX_SUCCESS;
}

/**
 * @brief Escapes double quotes and backslashes in a filesystem path for safe
 * inclusion in a macOS Seatbelt Profile Language (SBPL) string literal.
 * @param raw_path The unescaped host directory path.
 * @param out_escaped Pointer to receive the newly allocated escaped string.
 * @return SANDBOX_SUCCESS on success, or an error enum on failure.
 */
sandbox_error_t sandbox_escape_sbpl_path(const char *raw_path,
                                         char **out_escaped) {
  sandbox_error_t rc;
  const char *p;
  size_t extra = 0;
  size_t base_len = 0;
  void *raw_buf = NULL;
  char *dst;
  if (!raw_path || !out_escaped) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  *out_escaped = NULL;
  for (p = raw_path; *p != 0; p++) {
    base_len++;
    if (*p == 34 || *p == 92) {
      extra++;
    }
  }
  rc = sandbox_alloc(base_len + extra + 1, &raw_buf);
  if (rc != SANDBOX_SUCCESS) {
    return rc;
  }
  dst = (char *)raw_buf;
  *out_escaped = dst;
  for (p = raw_path; *p != 0; p++) {
    if (*p == 34 || *p == 92) {
      *dst++ = 92;
    }
    *dst++ = *p;
  }
  *dst = 0;
  return SANDBOX_SUCCESS;
}

/**
 * @brief Computes Windows Job Object limit parameters from a sandbox_config_t.
 * @param config The sandbox configuration parameters.
 * @param out_limits Pointer to store the computed Job Object limits.
 * @return SANDBOX_SUCCESS on success, or SANDBOX_ERR_INVALID_ARG if NULL.
 */
sandbox_error_t sandbox_configure_job_limits(const sandbox_config_t *config,
                                             sandbox_job_limits_t *out_limits) {
  if (!config || !out_limits) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  out_limits->limit_flags = SANDBOX_JOB_LIMIT_ACTIVE_PROCESS |
                            SANDBOX_JOB_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
                            SANDBOX_JOB_LIMIT_KILL_ON_JOB_CLOSE;
  out_limits->active_process_limit = 64u;
  out_limits->process_memory_bytes = 0UL;
  out_limits->cpu_rate_percent = 0u;
  if (config->max_memory_mb > 0) {
    out_limits->limit_flags |= SANDBOX_JOB_LIMIT_PROCESS_MEMORY;
    out_limits->process_memory_bytes =
        (unsigned long)config->max_memory_mb * 1024UL * 1024UL;
  }
  if (config->max_cpu_percent > 0) {
    out_limits->cpu_rate_percent =
        config->max_cpu_percent > 100u ? 100u : config->max_cpu_percent;
  }
  return SANDBOX_SUCCESS;
}

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
                                       int *exit_status) {
#if !defined(SANDBOX_ENABLE_MOCKS)
  int status = -1;
#endif
  sandbox_error_t rc = SANDBOX_SUCCESS;
  if (!bin_name || !exec_argv || !config || !exit_status) {
    return SANDBOX_ERR_INVALID_ARG;
  }

#if defined(SANDBOX_ENABLE_MOCKS)
  if (out_fp) {
    fputs("mock_stdout", out_fp);
    fflush(out_fp);
  }
  if (err_fp) {
    fputs("mock_stderr", err_fp);
    fflush(err_fp);
  }
  if (g_sandbox_mock_spawn_mode == 1) {
    rc = LOG_DEBUG("Execute failed: mock failure for %s", bin_name);
    if (rc != SANDBOX_SUCCESS) {
      return rc;
    }
    return SANDBOX_ERR_EXEC_FAILED;
  }
  if (g_sandbox_mock_spawn_mode == 2) {
    *exit_status = 124;
    return SANDBOX_SUCCESS;
  }
  if (g_sandbox_mock_spawn_mode == 4) {
    *exit_status = 42;
    return SANDBOX_SUCCESS;
  }
  if (g_sandbox_mock_spawn_mode == 5) {
    *exit_status = -5;
    return SANDBOX_SUCCESS;
  }
  *exit_status = 0;
  return SANDBOX_SUCCESS;
#else
#if defined(_WIN32) || defined(__WATCOMC__)
  {
    int old_out = -1;
    int old_err = -1;
    if (out_fp) {
      old_out = _dup(1);
      if (old_out != -1) {
        _dup2(_fileno(out_fp), 1);
      }
    }
    if (err_fp) {
      old_err = _dup(2);
      if (old_err != -1) {
        _dup2(_fileno(err_fp), 2);
      }
    }

    if (config->timeout_secs > 0) {
#ifdef _WIN32
      intptr_t hProcess = PLATFORM_SPAWNVP(PLATFORM_P_NOWAIT, bin_name,
                                           (const char *const *)exec_argv);
      if (hProcess != -1) {
        if (WaitForSingleObject((HANDLE)hProcess,
                                config->timeout_secs * 1000) == WAIT_TIMEOUT) {
          TerminateProcess((HANDLE)hProcess, 1);
          status = 124;
        } else {
          DWORD exit_code = 0;
          if (GetExitCodeProcess((HANDLE)hProcess, &exit_code)) {
            status = (int)exit_code;
          }
        }
        CloseHandle((HANDLE)hProcess);
      }
#else
      status = (int)PLATFORM_SPAWNVP(PLATFORM_P_WAIT, bin_name,
                                     (const char *const *)exec_argv);
#endif
    } else {
      status = (int)PLATFORM_SPAWNVP(PLATFORM_P_WAIT, bin_name,
                                     (const char *const *)exec_argv);
    }

    if (old_out != -1) {
      _dup2(old_out, 1);
      _close(old_out);
    }
    if (old_err != -1) {
      _dup2(old_err, 2);
      _close(old_err);
    }
  }
#else
  {
    pid_t pid = fork();
    if (pid < 0) {
      status = -1;
    } else if (pid == 0) {
      setpgid(0, 0);
      if (config->max_memory_mb > 0) {
        struct rlimit rl;
        rl.rlim_cur = (rlim_t)config->max_memory_mb * 1024U * 1024U;
        rl.rlim_max = rl.rlim_cur;
        setrlimit(RLIMIT_AS, &rl);
      }
      if (config->drop_privileges) {
        if (config->target_gid > 0) {
          setgid((gid_t)config->target_gid);
        }
        if (config->target_uid > 0) {
          setuid((uid_t)config->target_uid);
        }
      }
      if (config->env_vars) {
        size_t e;
        for (e = 0; e < config->env_count; e++) {
          if (config->env_vars[e]) {
            putenv((char *)config->env_vars[e]);
          }
        }
      }
      if (out_fp) {
        dup2(fileno(out_fp), STDOUT_FILENO);
      }
      if (err_fp) {
        dup2(fileno(err_fp), STDERR_FILENO);
      }
      execvp(bin_name, exec_argv);
      _exit(127);
    } else {
      int wstatus = 0;
      if (config->timeout_secs > 0) {
        unsigned int max_polls = config->timeout_secs * 10;
        unsigned int polls = 0;
        pid_t wp = 0;
        while (polls < max_polls) {
          wp = waitpid(pid, &wstatus, WNOHANG);
          if (wp != 0) {
            break;
          }
          {
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
            select(0, NULL, NULL, NULL, &tv);
          }
          polls++;
        }
        if (wp == 0) {
          kill(-pid, SIGKILL);
          kill(pid, SIGKILL);
          waitpid(pid, &wstatus, 0);
          status = 124;
        } else if (wp > 0 && WIFEXITED(wstatus)) {
          status = WEXITSTATUS(wstatus);
        } else {
          status = -1;
        }
      } else {
        if (waitpid(pid, &wstatus, 0) > 0 && WIFEXITED(wstatus)) {
          status = WEXITSTATUS(wstatus);
        } else {
          status = -1;
        }
      }
    }
  }
#endif

  if (status == -1) {
    rc = LOG_DEBUG("Execute failed for %s", bin_name);
    if (rc != SANDBOX_SUCCESS) {
      return rc;
    }
    return SANDBOX_ERR_EXEC_FAILED;
  }
  *exit_status = status;
  return SANDBOX_SUCCESS;
#endif
}
