/**
 * @file engine_podman.c
 * @brief Podman-based sandbox implementation.
 *
 * This engine maps the execution of a command into a Podman container.
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
 * @brief Initializes the Podman engine.
 * @return SANDBOX_SUCCESS on initialization.
 */
static sandbox_error_t podman_init(void) { return SANDBOX_SUCCESS; }

/**
 * @brief Executes a command inside a Podman container.
 * @param config The sandbox configuration parameters.
 * @param argc Number of command arguments.
 * @param argv Array of command arguments.
 * @param exit_status Pointer to receive the exit code of the Podman process.
 * @return SANDBOX_SUCCESS on success, or an error enum on failure.
 */
static sandbox_error_t podman_execute(const sandbox_config_t *config, int argc,
                                      char **argv, int *exit_status) {
  sandbox_error_t rc = SANDBOX_SUCCESS;
  void *raw_ptr = NULL;
  char **podman_argv = NULL;
  int i;
  int status = -1;
  char **vstr_array = NULL;
  size_t allocated_mounts = 0;
  int base_args = 10;
  int current_arg = 0;
  FILE *out_fp = NULL;
  FILE *err_fp = NULL;
  char mem_buf[32];
  char cpu_buf[32];
  char *sec_buf_ptr = NULL;
  char *app_buf_ptr = NULL;
  char user_buf[64];

  if (!config || argc < 0 || !argv) {
    return SANDBOX_ERR_INVALID_ARG;
  }

  if (config->max_network_mbps > 0) {
    fprintf(stderr,
            "[libmountsandbox] Warning: Network bandwidth throttling "
            "(max_network_mbps) is not natively enforced by this engine.\x0a");
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

  if (config->use_pty) {
    base_args += 2;
  }
  if (config->disable_network) {
    base_args += 2;
  }
  if (config->seccomp_profile_path) {
    base_args += 2;
  }
  if (config->apparmor_profile) {
    base_args += 2;
  }
  if (config->max_memory_mb > 0) {
    base_args += 2;
  }
  if (config->max_cpu_percent > 0) {
    base_args += 2;
  }
  if (config->drop_privileges) {
    base_args += 4;
  }
  if (config->denied_syscalls) {
    base_args += (int)(config->denied_syscall_count * 2);
  }
  if (config->env_vars) {
    base_args += (int)(config->env_count * 2);
  }
  if (config->mounts) {
    base_args += (int)(config->mount_count * 2);
  }

  rc = sandbox_alloc((size_t)(argc + base_args + 1) * sizeof(char *), &raw_ptr);
  if (rc != SANDBOX_SUCCESS) {
    goto cleanup;
  }
  podman_argv = (char **)raw_ptr;

  podman_argv[current_arg++] = (char *)"podman";
  podman_argv[current_arg++] = (char *)"run";
  podman_argv[current_arg++] = (char *)"--rm";
  podman_argv[current_arg++] = (char *)"--pids-limit";
  podman_argv[current_arg++] = (char *)"256";

  if (config->disable_network) {
    podman_argv[current_arg++] = (char *)"--network";
    podman_argv[current_arg++] = (char *)"none";
  }
  if (config->use_pty) {
    podman_argv[current_arg++] = (char *)"-i";
    podman_argv[current_arg++] = (char *)"-t";
  }
  if (config->seccomp_profile_path) {
    size_t sec_len = strlen(config->seccomp_profile_path) + 15;
    rc = sandbox_alloc(sec_len, &raw_ptr);
    if (rc != SANDBOX_SUCCESS) {
      goto cleanup;
    }
    sec_buf_ptr = (char *)raw_ptr;
#if defined(_MSC_VER)
    sprintf_s(sec_buf_ptr, sec_len, "seccomp=%s", config->seccomp_profile_path);
#else
    sprintf(sec_buf_ptr, "seccomp=%s", config->seccomp_profile_path);
#endif
    podman_argv[current_arg++] = (char *)"--security-opt";
    podman_argv[current_arg++] = sec_buf_ptr;
  }
  if (config->apparmor_profile) {
    size_t app_len = strlen(config->apparmor_profile) + 15;
    rc = sandbox_alloc(app_len, &raw_ptr);
    if (rc != SANDBOX_SUCCESS) {
      goto cleanup;
    }
    app_buf_ptr = (char *)raw_ptr;
#if defined(_MSC_VER)
    sprintf_s(app_buf_ptr, app_len, "apparmor=%s", config->apparmor_profile);
#else
    sprintf(app_buf_ptr, "apparmor=%s", config->apparmor_profile);
#endif
    podman_argv[current_arg++] = (char *)"--security-opt";
    podman_argv[current_arg++] = app_buf_ptr;
  }

  if (config->max_memory_mb > 0) {
#if defined(_MSC_VER)
    sprintf_s(mem_buf, sizeof(mem_buf), SANDBOX_UINT_FMT "m",
              config->max_memory_mb);
#else
    sprintf(mem_buf, SANDBOX_UINT_FMT "m", config->max_memory_mb);
#endif
    podman_argv[current_arg++] = (char *)"--memory";
    podman_argv[current_arg++] = mem_buf;
  }

  if (config->max_cpu_percent > 0) {
#if defined(_MSC_VER)
    sprintf_s(cpu_buf, sizeof(cpu_buf), SANDBOX_UINT_FMT ".%02u",
              config->max_cpu_percent / 100, config->max_cpu_percent % 100);
#else
    sprintf(cpu_buf, SANDBOX_UINT_FMT ".%02u", config->max_cpu_percent / 100,
            config->max_cpu_percent % 100);
#endif
    podman_argv[current_arg++] = (char *)"--cpus";
    podman_argv[current_arg++] = cpu_buf;
  }

  if (config->drop_privileges) {
    if (config->target_uid != 0 || config->target_gid != 0) {
#if defined(_MSC_VER)
      sprintf_s(user_buf, sizeof(user_buf),
                SANDBOX_UINT_FMT ":" SANDBOX_UINT_FMT, config->target_uid,
                config->target_gid);
#else
      sprintf(user_buf, SANDBOX_UINT_FMT ":" SANDBOX_UINT_FMT,
              config->target_uid, config->target_gid);
#endif
    } else {
#if defined(_MSC_VER)
      strcpy_s(user_buf, sizeof(user_buf), "65534:65534");
#else
      strcpy(user_buf, "65534:65534");
#endif
    }
    podman_argv[current_arg++] = (char *)"--security-opt";
    podman_argv[current_arg++] = (char *)"no-new-privileges";
    podman_argv[current_arg++] = (char *)"-u";
    podman_argv[current_arg++] = user_buf;
  }

  if (config->denied_syscalls) {
    size_t c;
    fprintf(stderr, "[libmountsandbox] Warning: Translating Podman syscall "
                    "deny into capabilities drop (approximate).\x0a");
    for (c = 0; c < config->denied_syscall_count; c++) {
      podman_argv[current_arg++] = (char *)"--cap-drop";
      podman_argv[current_arg++] = (char *)config->denied_syscalls[c];
    }
  }

  if (config->env_vars) {
    size_t e;
    for (e = 0; e < config->env_count; e++) {
      podman_argv[current_arg++] = (char *)"-e";
      podman_argv[current_arg++] = (char *)config->env_vars[e];
    }
  }

  if (config->mounts) {
    size_t m;
    rc = sandbox_alloc(config->mount_count * sizeof(char *), &raw_ptr);
    if (rc != SANDBOX_SUCCESS) {
      goto cleanup;
    }
    vstr_array = (char **)raw_ptr;
    for (m = 0; m < config->mount_count; m++) {
      size_t vlen = strlen(config->mounts[m].dir) + 25;
      char *vstr = NULL;
      rc = sandbox_alloc(vlen, &raw_ptr);
      if (rc != SANDBOX_SUCCESS) {
        goto cleanup;
      }
      vstr = (char *)raw_ptr;
#if defined(_MSC_VER)
      sprintf_s(vstr, vlen, "%s:/workspace" SANDBOX_ULONG_FMT "%s",
                config->mounts[m].dir, (unsigned long)m,
                config->mounts[m].read_only ? ":ro" : "");
#else
      sprintf(vstr, "%s:/workspace" SANDBOX_ULONG_FMT "%s",
              config->mounts[m].dir, (unsigned long)m,
              config->mounts[m].read_only ? ":ro" : "");
#endif
      vstr_array[allocated_mounts++] = vstr;
      podman_argv[current_arg++] = (char *)"-v";
      podman_argv[current_arg++] = vstr;
    }
  }

  podman_argv[current_arg++] = (char *)"-w";
  if (config->mounts) {
    podman_argv[current_arg++] = (char *)"/workspace0";
  } else {
    podman_argv[current_arg++] = (char *)"/";
  }
  podman_argv[current_arg++] = (char *)"ubuntu:latest";

  for (i = 0; i < argc; i++) {
    podman_argv[current_arg++] = argv[i];
  }
  podman_argv[current_arg] = NULL;

  rc = sandbox_spawn_and_wait("podman", podman_argv, config, out_fp, err_fp,
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
  if (vstr_array) {
    size_t j;
    for (j = 0; j < allocated_mounts; j++) {
      free(vstr_array[j]);
    }
    free(vstr_array);
  }
  if (sec_buf_ptr) {
    free(sec_buf_ptr);
  }
  if (app_buf_ptr) {
    free(app_buf_ptr);
  }
  if (podman_argv) {
    free(podman_argv);
  }
  return rc;
}

/**
 * @brief Executes a command in the sandbox asynchronously.
 * @param config Sandbox configuration.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @param out_process Pointer to receive the process handle.
 * @return SANDBOX_ERR_UNSUPPORTED as async is not yet implemented for podman.
 */
static sandbox_error_t podman_execute_async(const sandbox_config_t *config,
                                            int argc, char **argv,
                                            sandbox_process_t **out_process) {
  if (!config || argc < 0 || !argv) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  fprintf(stderr, "[libmountsandbox] Async execution is a work in progress for "
                  "podman. Falling back to sync.\x0a");
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
static sandbox_error_t podman_wait_process(sandbox_process_t *process,
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
static sandbox_error_t podman_free_process(sandbox_process_t *process) {
  if (process) {
    free(process);
  }
  return SANDBOX_SUCCESS;
}

/**
 * @brief Cleans up the engine resources.
 * @return SANDBOX_SUCCESS on completion.
 */
static sandbox_error_t podman_cleanup(void) { return SANDBOX_SUCCESS; }

/**
 * @brief The Podman sandbox engine export.
 */
sandbox_engine_t engine_podman = {"podman",
                                  "Podman-based rootless container sandbox",
                                  podman_init,
                                  podman_execute,
                                  podman_execute_async,
                                  podman_wait_process,
                                  podman_free_process,
                                  podman_cleanup};
