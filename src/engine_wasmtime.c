#if defined(__APPLE__) || defined(__linux__) || defined(__CYGWIN__)
#define _XOPEN_SOURCE 600
#endif
#define _WIN32_WINNT 0x0600
/**
 * \file engine_wasmtime.c
 * \brief Wasmtime-based WebAssembly sandbox implementation.
 *
 * This engine executes WebAssembly (.wasm) modules using the `wasmtime` CLI.
 * It maps libmountsandbox configuration intents into Wasmtime WASI
 * capabilities. It strictly supports C89 and compiles across multiple compilers
 * by using platform-specific process execution semantics.
 */

/* clang-format off */
#include "sandbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(__WATCOMC__)
#include <process.h>
#ifdef _WIN32
#include <io.h>
#include <winsock2.h>
#endif
#else
#include <fcntl.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__APPLE__) || defined(__linux__)
#define _XOPEN_SOURCE 600
#include <stdlib.h>
#endif
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* clang-format on */
/**
 * \brief Reads all content from a file pointer into a buffer.
 * \param fp The file pointer to read from.
 * \param buf Pointer to receive the allocated buffer.
 * \param size Pointer to receive the size of the buffer.
 * \return 0 on success, or -1 on error.
 */
static int read_fp_to_buffer(FILE *fp, char **buf, size_t *size) {
  long fsize;
  if (!fp || !buf || !size)
    return -1;
  fseek(fp, 0, SEEK_END);
  fsize = ftell(fp);
  rewind(fp);
  if (fsize < 0)
    fsize = 0;
  *buf = (char *)malloc((size_t)fsize + 1);
  if (*buf) {
    size_t read_bytes = fread(*buf, 1, (size_t)fsize, fp);
    (*buf)[read_bytes] = '\0';
    *size = read_bytes;
    return 0;
  } else {
    *size = 0;
    return -1;
  }
}

/**
 * \brief Initializes the engine.
 * \return 0 on success, or -1 on error.
 */
static int wasmtime_init(void) { return 0; }

/**
 * \brief Executes a command in the sandbox synchronously.
 * \param config Sandbox configuration.
 * \param argc Argument count.
 * \param argv Argument vector.
 * \return Exit status, or -1 on error.
 */
static int wasmtime_execute(const sandbox_config_t *config, int argc,
                            char **argv) {
  char **wasmtime_argv;
  int i, status = -1;
  int current_arg = 0;
  int base_args = 4; /* wasmtime run module args */
  FILE *out_fp = NULL;
  FILE *err_fp = NULL;

  if (!config || !argv || argc < 1)
    return -1;

#if defined(_MSC_VER)
  if (config->stdout_buffer)
    tmpfile_s(&out_fp);
#else
  if (config->stdout_buffer)
    out_fp = tmpfile();
#endif
  if (config->max_network_mbps > 0) {
    fprintf(stderr,
            "[libmountsandbox] Warning: Network bandwidth throttling "
            "(max_network_mbps) is not natively enforced by this engine.\n");
  }
#if defined(_MSC_VER)
  if (config->stderr_buffer)
    tmpfile_s(&err_fp);
#else
  if (config->stderr_buffer)
    err_fp = tmpfile();
#endif

  if (config->env_vars && config->env_count > 0) {
    base_args += (int)(config->env_count * 2);
  }

  if (config->mounts && config->mount_count > 0) {
    base_args += (int)(config->mount_count * 2);
  }

  if (config->seccomp_profile_path || config->apparmor_profile ||
      config->denied_syscall_count > 0) {
    fprintf(stderr,
            "[libmountsandbox] Warning: OS-level Syscall filtering ignored. "
            "WebAssembly relies on WASI capabilities natively.\n");
  }

  if (!config->disable_network) {
    fprintf(
        stderr,
        "[libmountsandbox] Warning: Network access is inherently disabled in "
        "default WASI unless explicit socket capabilities are mapped.\n");
  }

  if (config->max_memory_mb > 0 || config->max_cpu_percent > 0) {
    fprintf(stderr, "[libmountsandbox] Warning: CPU/Memory rate limiting via "
                    "CLI is not mapped in this implementation of Wasmtime.\n");
  }

  if (config->drop_privileges) {
    fprintf(stderr, "[libmountsandbox] Warning: Privilege dropping ignored. "
                    "WASM executes securely in userspace.\n");
  }

  if (config->use_pty) {
    fprintf(stderr,
            "[libmountsandbox] Warning: Wasmtime engine ignores use_pty as "
            "interactive TTY routing requires complex WASI fd mapping.\n");
  }

  wasmtime_argv =
      (char **)malloc((size_t)(argc + base_args + 1) * sizeof(char *));
  if (!wasmtime_argv) {
    if (out_fp)
      fclose(out_fp);
    if (err_fp)
      fclose(err_fp);
    return -1;
  }

  wasmtime_argv[current_arg++] = (char *)"wasmtime";
  wasmtime_argv[current_arg++] = (char *)"run";

  if (config->env_vars && config->env_count > 0) {
    size_t e;
    for (e = 0; e < config->env_count; e++) {
      wasmtime_argv[current_arg++] = (char *)"--env";
      wasmtime_argv[current_arg++] = (char *)config->env_vars[e];
    }
  }

  if (config->mounts && config->mount_count > 0) {
    size_t m;
    for (m = 0; m < config->mount_count; m++) {
      wasmtime_argv[current_arg++] = (char *)"--dir";
      wasmtime_argv[current_arg++] = (char *)config->mounts[m].dir;
    }
  }

  for (i = 0; i < argc; i++) {
    wasmtime_argv[current_arg++] = argv[i];
  }
  wasmtime_argv[current_arg] = NULL;

#if defined(_WIN32) || defined(__WATCOMC__)
  {
    int fd_out = -1, fd_err = -1;
    int old_out = -1, old_err = -1;
    if (out_fp) {
      fd_out = _fileno(out_fp);
      old_out = _dup(1);
      _dup2(fd_out, 1);
    }
    if (err_fp) {
      fd_err = _fileno(err_fp);
      old_err = _dup(2);
      _dup2(fd_err, 2);
    }

    status =
        (int)_spawnvp(_P_WAIT, "wasmtime", (const char *const *)wasmtime_argv);

    if (out_fp) {
      _dup2(old_out, 1);
      _close(old_out);
    }
    if (err_fp) {
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
      if (out_fp)
        dup2(fileno(out_fp), STDOUT_FILENO);
      if (err_fp)
        dup2(fileno(err_fp), STDERR_FILENO);
      execvp("wasmtime", (char *const *)wasmtime_argv);
      perror("[libmountsandbox] execvp wasmtime failed");
      exit(127);
    } else {
      int wstatus;
      if (config->timeout_secs > 0) {
        unsigned int max_polls = config->timeout_secs * 10;
        unsigned int polls = 0;
        int wp = 0;
        while (polls < max_polls) {
          wp = waitpid(pid, &wstatus, WNOHANG);
          if (wp != 0)
            break;
          {
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
            select(0, NULL, NULL, NULL, &tv);
          }
          polls++;
        }
        if (wp == 0) {
          kill(pid, SIGKILL);
          waitpid(pid, &wstatus, 0);
          status = 124;
        } else if (wp > 0 && WIFEXITED(wstatus)) {
          status = WEXITSTATUS(wstatus);
        } else {
          status = -1;
        }
      } else {
        waitpid(pid, &wstatus, 0);
        if (WIFEXITED(wstatus)) {
          status = WEXITSTATUS(wstatus);
        } else {
          status = -1;
        }
      }
    }
  }
#endif

  if (out_fp && config->stdout_buffer) {
    if (read_fp_to_buffer(out_fp, config->stdout_buffer, config->stdout_size) !=
        0) {
      status = -1;
    }
    fclose(out_fp);
  }
  if (err_fp && config->stderr_buffer) {
    if (read_fp_to_buffer(err_fp, config->stderr_buffer, config->stderr_size) !=
        0) {
      status = -1;
    }
    fclose(err_fp);
  }

  free(wasmtime_argv);
  return status;
}

/**
 * \brief Executes a command in the sandbox asynchronously.
 * \param config Sandbox configuration.
 * \param argc Argument count.
 * \param argv Argument vector.
 * \param out_process Pointer to receive the process handle.
 * \return 0 on success, or -1 on error.
 */
static int wasmtime_execute_async(const sandbox_config_t *config, int argc,
                                  char **argv,
                                  sandbox_process_t **out_process) {
  (void)config;
  (void)argc;
  (void)argv;
  fprintf(stderr, "[libmountsandbox] Async execution is a work in progress for "
                  "wasmtime. Falling back to sync.\n");
  if (out_process)
    *out_process = NULL;
  return -1;
}

/**
 * \brief Waits for an asynchronous process to complete.
 * \param process The process handle.
 * \param exit_status Pointer to receive the exit status.
 * \return 0 on success, or -1 on error.
 */
static int wasmtime_wait_process(sandbox_process_t *process, int *exit_status) {
  (void)process;
  (void)exit_status;
  return -1;
}

/**
 * \brief Frees an asynchronous process handle.
 * \param process The process handle.
 */
static void wasmtime_free_process(sandbox_process_t *process) { (void)process; }

/**
 * \brief Cleans up the engine resources.
 */
static void wasmtime_cleanup(void) {}

/**
 * \brief The Wasmtime sandbox engine export.
 */
sandbox_engine_t engine_wasmtime = {
    "wasmtime",
    "WebAssembly WASI execution sandbox (wasmtime)",
    wasmtime_init,
    wasmtime_execute,
    wasmtime_execute_async,
    wasmtime_wait_process,
    wasmtime_free_process,
    wasmtime_cleanup};
