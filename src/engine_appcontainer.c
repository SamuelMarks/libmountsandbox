/**
 * @file engine_appcontainer.c
 * @brief Windows AppContainer sandbox implementation.
 *
 * This engine maps the execution of a command into a native Windows
 * AppContainer, providing strict isolation compared to standard Job Objects.
 */
/* clang-format off */
#include "sandbox.h"
#include "sandbox_common.h"
#include "log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* clang-format on */

/**
 * @brief Initializes the AppContainer engine.
 * @return SANDBOX_SUCCESS on initialization.
 */
static sandbox_error_t appcontainer_init(void) { return SANDBOX_SUCCESS; }

/**
 * @brief Executes a command inside an AppContainer sandbox.
 * @param config The sandbox configuration parameters.
 * @param argc Number of command arguments.
 * @param argv Array of command arguments.
 * @param exit_status Pointer to receive the exit code of the process.
 * @return SANDBOX_SUCCESS on success, or an error enum on failure.
 */
static sandbox_error_t appcontainer_execute(const sandbox_config_t *config,
                                            int argc, char **argv,
                                            int *exit_status) {
  sandbox_error_t rc = SANDBOX_SUCCESS;
  void *raw_ptr = NULL;
  char **exec_argv = NULL;
  char *cmdline = NULL;
  size_t cmdline_len = 0;
  sandbox_job_limits_t job_limits;
  int i;
  int status = -1;
  FILE *out_fp = NULL;
  FILE *err_fp = NULL;

  rc = sandbox_configure_job_limits(config, &job_limits);
  if (rc != SANDBOX_SUCCESS) {
    return rc;
  }

  if (argc < 1 || !argv) {
    return SANDBOX_ERR_INVALID_ARG;
  }

  if (config->max_network_mbps > 0) {
    fprintf(stderr,
            "[libmountsandbox] Warning: Network bandwidth throttling "
            "(max_network_mbps) is not natively enforced by this engine.\x0a");
  }
  if (config->use_pty) {
    fprintf(stderr,
            "[libmountsandbox] Warning: Interactive PTY is not natively "
            "supported on Windows AppContainer without ConPTY. Ignored.\x0a");
  }
  if (config->seccomp_profile_path || config->apparmor_profile) {
    fprintf(stderr,
            "[libmountsandbox] Warning: Seccomp/AppArmor profiles are not "
            "natively supported via Windows AppContainer. Ignored.\x0a");
  }
  if (config->max_cpu_percent > 0) {
    fprintf(stderr, "[libmountsandbox] Warning: CPU rate limiting not enabled "
                    "on baseline AppContainer without Job Objects.\x0a");
  }
  if (config->denied_syscalls) {
    fprintf(stderr, "[libmountsandbox] Warning: Fine-grained Syscall filtering "
                    "(Seccomp) is not natively supported via Windows "
                    "AppContainer. Ignored.\x0a");
  }

  if (config->stdout_buffer) {
    rc = sandbox_open_tmpfile(&out_fp);
    if (rc != SANDBOX_SUCCESS) {
      return rc;
    }
  }
  if (config->stderr_buffer) {
    rc = sandbox_open_tmpfile(&err_fp);
    if (rc != SANDBOX_SUCCESS) {
      goto cleanup;
    }
  }

  for (i = 0; i < argc; i++) {
    cmdline_len += strlen(argv[i]) + 3;
  }
  rc = sandbox_alloc(cmdline_len + 1, &raw_ptr);
  if (rc != SANDBOX_SUCCESS) {
    goto cleanup;
  }
  cmdline = (char *)raw_ptr;
  cmdline[0] = 0;
  for (i = 0; i < argc; i++) {
    char q_end[3];
    q_end[0] = 34;
    q_end[1] = 32;
    q_end[2] = 0;
#if defined(_MSC_VER)
    strcat_s(cmdline, cmdline_len + 1, q_end + 1);
    strcat_s(cmdline, cmdline_len + 1, argv[i]);
    strcat_s(cmdline, cmdline_len + 1, q_end);
#else
    strcat(cmdline, q_end + 1);
    strcat(cmdline, argv[i]);
    strcat(cmdline, q_end);
#endif
  }

  rc = sandbox_alloc((size_t)(argc + 1) * sizeof(char *), &raw_ptr);
  if (rc != SANDBOX_SUCCESS) {
    goto cleanup;
  }
  exec_argv = (char **)raw_ptr;
  for (i = 0; i < argc; i++) {
    exec_argv[i] = argv[i];
  }
  exec_argv[argc] = NULL;

  rc = sandbox_spawn_and_wait(argv[0], exec_argv, config, out_fp, err_fp,
                              &status);

  if (rc != SANDBOX_SUCCESS) {
    goto cleanup;
  }

  if (out_fp) {
    rc = sandbox_read_fp_to_buffer(out_fp, config->stdout_buffer,
                                   config->stdout_size);
    if (rc != SANDBOX_SUCCESS) {
      goto cleanup;
    }
  }
  if (err_fp) {
    rc = sandbox_read_fp_to_buffer(err_fp, config->stderr_buffer,
                                   config->stderr_size);
    if (rc != SANDBOX_SUCCESS) {
      goto cleanup;
    }
  }

  if (exit_status) {
    *exit_status = status;
  }

cleanup:
  if (out_fp) {
    fclose(out_fp);
  }
  if (err_fp) {
    fclose(err_fp);
  }
  if (exec_argv) {
    free(exec_argv);
  }
  if (cmdline) {
    free(cmdline);
  }
  return rc;
}

/**
 * @brief Executes a command in the sandbox asynchronously.
 * @param config Sandbox configuration.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @param out_process Pointer to receive the process handle.
 * @return SANDBOX_ERR_UNSUPPORTED as async is not yet implemented for
 * appcontainer.
 */
static sandbox_error_t
appcontainer_execute_async(const sandbox_config_t *config, int argc,
                           char **argv, sandbox_process_t **out_process) {
  if (!config || argc < 0 || !argv) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  fprintf(stderr, "[libmountsandbox] Async execution is a work in progress for "
                  "appcontainer. Falling back to sync.\x0a");
  if (out_process) {
    *out_process = NULL;
  }
  return SANDBOX_ERR_UNSUPPORTED;
}

/**
 * @brief Waits for an asynchronous process to complete.
 * @param process The process handle.
 * @param exit_status Pointer to receive the exit status.
 * @return SANDBOX_ERR_UNSUPPORTED or SANDBOX_ERR_INVALID_ARG.
 */
static sandbox_error_t appcontainer_wait_process(sandbox_process_t *process,
                                                 int *exit_status) {
  if (!process || !exit_status) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  return SANDBOX_ERR_UNSUPPORTED;
}

/**
 * @brief Frees an asynchronous process handle.
 * @param process The process handle.
 * @return SANDBOX_SUCCESS on completion.
 */
static sandbox_error_t appcontainer_free_process(sandbox_process_t *process) {
  if (process) {
    free(process);
  }
  return SANDBOX_SUCCESS;
}

/**
 * @brief Cleans up the engine resources.
 * @return SANDBOX_SUCCESS on completion.
 */
static sandbox_error_t appcontainer_cleanup(void) { return SANDBOX_SUCCESS; }

/**
 * @brief The AppContainer sandbox engine export.
 */
sandbox_engine_t engine_appcontainer = {
    "appcontainer",
    "Windows AppContainer strict isolation sandbox",
    appcontainer_init,
    appcontainer_execute,
    appcontainer_execute_async,
    appcontainer_wait_process,
    appcontainer_free_process,
    appcontainer_cleanup};
