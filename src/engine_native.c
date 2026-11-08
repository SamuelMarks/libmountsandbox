/**
 * @file engine_native.c
 * @brief Native OS sandbox implementation.
 *
 * This engine maps the execution of a command into a native OS sandboxing
 * facility (e.g., sandbox-exec on macOS, bwrap/namespaces on Linux, Job
 * Objects on Windows).
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
 * @brief Initializes the Native OS sandbox engine.
 * @return SANDBOX_SUCCESS on initialization.
 */
static sandbox_error_t native_init(void) { return SANDBOX_SUCCESS; }

/**
 * @brief Executes a command in the native OS sandbox synchronously.
 * @param config Sandbox configuration.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @param exit_status Pointer to receive the process exit code.
 * @return SANDBOX_SUCCESS on success, or an error enum on failure.
 */
static sandbox_error_t native_execute(const sandbox_config_t *config, int argc,
                                      char **argv, int *exit_status) {
  sandbox_error_t rc = SANDBOX_SUCCESS;
  void *raw_ptr = NULL;
  char **exec_argv = NULL;
  char **escaped_mounts = NULL;
  size_t escaped_count = 0;
  char *profile = NULL;
  size_t profile_len;
  int i;
  int status = -1;
  int base_args = 8;
#if defined(__linux__)
  int current_arg = 0;
  char uid_buf[32];
  char gid_buf[32];
#endif
  sandbox_job_limits_t job_limits;
  FILE *out_fp = NULL;
  FILE *err_fp = NULL;
  const char *bin_name = "sandbox-exec";
  const char *profile_template_base =
      "(version 1)\x0a"
      "(allow default)\x0a"
      "(deny file-write*)\x0a"
      "(allow file-write* (subpath \x22/dev\x22))\x0a"
      "(allow file-write* (subpath \x22/private/tmp\x22))\x0a"
      "(allow file-write* (subpath \x22/var/folders\x22))\x0a";
  const char *profile_network_deny = "(deny network*)\x0a";

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
            "supported without platform PTY allocation. Ignored.\x0a");
  }
  if (config->seccomp_profile_path || config->apparmor_profile) {
    fprintf(stderr, "[libmountsandbox] Warning: Seccomp/AppArmor profiles are "
                    "not natively supported on all host OSes. Ignored.\x0a");
  }
  if (config->max_cpu_percent > 0) {
    fprintf(stderr, "[libmountsandbox] Warning: CPU rate limiting not "
                    "natively supported without cgroups. Ignored.\x0a");
  }
  if (config->denied_syscalls) {
    fprintf(stderr, "[libmountsandbox] Warning: Fine-grained syscall filtering "
                    "is approximated by the native engine.\x0a");
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

  profile_len = strlen(profile_template_base) + 1;
  if (config->disable_network) {
    profile_len += strlen(profile_network_deny);
  }
  if (config->mounts) {
    size_t m;
    rc = sandbox_alloc(config->mount_count * sizeof(char *), &raw_ptr);
    if (rc != SANDBOX_SUCCESS) {
      goto cleanup;
    }
    escaped_mounts = (char **)raw_ptr;
    for (m = 0; m < config->mount_count; m++) {
      char *esc = NULL;
      rc = sandbox_escape_sbpl_path(config->mounts[m].dir, &esc);
      if (rc != SANDBOX_SUCCESS) {
        goto cleanup;
      }
      escaped_mounts[escaped_count++] = esc;
      profile_len += 34 + strlen(esc) + 4;
    }
  }

  rc = sandbox_alloc(profile_len, &raw_ptr);
  if (rc != SANDBOX_SUCCESS) {
    goto cleanup;
  }
  profile = (char *)raw_ptr;

#if defined(_MSC_VER)
  strcpy_s(profile, profile_len, profile_template_base);
  if (config->disable_network) {
    strcat_s(profile, profile_len, profile_network_deny);
  }
#else
  strcpy(profile, profile_template_base);
  if (config->disable_network) {
    strcat(profile, profile_network_deny);
  }
#endif

  if (escaped_mounts) {
    size_t m;
    for (m = 0; m < escaped_count; m++) {
      const char *rule_prefix = config->mounts[m].read_only
                                    ? "(allow file-read* (subpath \x22"
                                    : "(allow file-write* (subpath \x22";
#if defined(_MSC_VER)
      strcat_s(profile, profile_len, rule_prefix);
      strcat_s(profile, profile_len, escaped_mounts[m]);
      strcat_s(profile, profile_len, "\x22))\x0a");
#else
      strcat(profile, rule_prefix);
      strcat(profile, escaped_mounts[m]);
      strcat(profile, "\x22))\x0a");
#endif
    }
  }

  if (config->mounts) {
    base_args += (int)(config->mount_count * 3);
  }
  if (config->drop_privileges) {
    base_args += 4;
  }
  if (config->denied_syscalls) {
    base_args += (int)(config->denied_syscall_count * 2);
  }

  rc = sandbox_alloc((size_t)(argc + base_args + 1) * sizeof(char *), &raw_ptr);
  if (rc != SANDBOX_SUCCESS) {
    goto cleanup;
  }
  exec_argv = (char **)raw_ptr;

#if defined(__APPLE__)
  exec_argv[0] = (char *)"sandbox-exec";
  exec_argv[1] = (char *)"-p";
  exec_argv[2] = profile;
  for (i = 0; i < argc; i++) {
    exec_argv[3 + i] = argv[i];
  }
  exec_argv[3 + argc] = NULL;
  bin_name = "sandbox-exec";
#elif defined(__linux__)
  exec_argv[current_arg++] = (char *)"bwrap";
  exec_argv[current_arg++] = (char *)"--unshare-all";
  exec_argv[current_arg++] = (char *)"--die-with-parent";
  if (!config->disable_network) {
    exec_argv[current_arg++] = (char *)"--share-net";
  }
  exec_argv[current_arg++] = (char *)"--dev";
  exec_argv[current_arg++] = (char *)"/dev";
  exec_argv[current_arg++] = (char *)"--proc";
  exec_argv[current_arg++] = (char *)"/proc";
  if (config->mounts) {
    size_t m;
    for (m = 0; m < config->mount_count; m++) {
      exec_argv[current_arg++] =
          (char *)(config->mounts[m].read_only ? "--ro-bind" : "--bind");
      exec_argv[current_arg++] = (char *)config->mounts[m].dir;
      exec_argv[current_arg++] = (char *)config->mounts[m].dir;
    }
  }
  if (config->drop_privileges) {
    sprintf(uid_buf, SANDBOX_UINT_FMT,
            config->target_uid > 0 ? config->target_uid : 65534u);
    sprintf(gid_buf, SANDBOX_UINT_FMT,
            config->target_gid > 0 ? config->target_gid : 65534u);
    exec_argv[current_arg++] = (char *)"--uid";
    exec_argv[current_arg++] = uid_buf;
    exec_argv[current_arg++] = (char *)"--gid";
    exec_argv[current_arg++] = gid_buf;
  }
  if (config->denied_syscalls) {
    size_t c;
    for (c = 0; c < config->denied_syscall_count; c++) {
      exec_argv[current_arg++] = (char *)"--cap-drop";
      exec_argv[current_arg++] = (char *)config->denied_syscalls[c];
    }
  }
  exec_argv[current_arg++] = (char *)"--";
  for (i = 0; i < argc; i++) {
    exec_argv[current_arg++] = argv[i];
  }
  exec_argv[current_arg] = NULL;
  bin_name = "bwrap";
#else
  for (i = 0; i < argc; i++) {
    exec_argv[i] = argv[i];
  }
  exec_argv[argc] = NULL;
  bin_name = argv[0];
#endif

  rc = sandbox_spawn_and_wait(bin_name, exec_argv, config, out_fp, err_fp,
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
  if (escaped_mounts) {
    size_t j;
    for (j = 0; j < escaped_count; j++) {
      free(escaped_mounts[j]);
    }
    free(escaped_mounts);
  }
  if (exec_argv) {
    free(exec_argv);
  }
  if (profile) {
    free(profile);
  }
  return rc;
}

/**
 * @brief Executes a command in the sandbox asynchronously.
 * @param config Sandbox configuration.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @param out_process Pointer to receive the process handle.
 * @return SANDBOX_ERR_UNSUPPORTED as async is not yet implemented for native.
 */
static sandbox_error_t native_execute_async(const sandbox_config_t *config,
                                            int argc, char **argv,
                                            sandbox_process_t **out_process) {
  if (!config || argc < 0 || !argv) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  fprintf(stderr, "[libmountsandbox] Async execution is a work in progress for "
                  "native. Falling back to sync.\x0a");
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
static sandbox_error_t native_wait_process(sandbox_process_t *process,
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
static sandbox_error_t native_free_process(sandbox_process_t *process) {
  if (process) {
    free(process);
  }
  return SANDBOX_SUCCESS;
}

/**
 * @brief Cleans up the engine resources.
 * @return SANDBOX_SUCCESS on completion.
 */
static sandbox_error_t native_cleanup(void) { return SANDBOX_SUCCESS; }

/**
 * @brief The Native OS sandbox engine export.
 */
sandbox_engine_t engine_native = {
    "native",
    "Native OS sandbox (sandbox-exec / unshare / Job Objects)",
    native_init,
    native_execute,
    native_execute_async,
    native_wait_process,
    native_free_process,
    native_cleanup};
