/**
 * \file main.c
 * \brief Command-line interface for libmountsandbox.
 */
/* clang-format off */
#include "sandbox.h"
#include "sandbox_common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* clang-format on */

/**
 * \brief Prints the version information.
 * \return SANDBOX_SUCCESS on completion.
 */
#if defined(SANDBOX_ENABLE_MOCKS)
int g_sandbox_mock_print_version_fail = 0;
#endif

static sandbox_error_t print_version(void) {
#if defined(SANDBOX_ENABLE_MOCKS)
  if (g_sandbox_mock_print_version_fail) {
    return SANDBOX_ERR_IO;
  }
#endif
  printf("libmountsandbox version 0.1.0\n");
  return SANDBOX_SUCCESS;
}

/**
 * \brief Prints the usage information.
 * \param prog_name The name of the program executable.
 * \return SANDBOX_SUCCESS on completion, or SANDBOX_ERR_INVALID_ARG if NULL.
 */
static sandbox_error_t print_usage(const char *prog_name) {
  if (!prog_name) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  fprintf(stderr, "Usage: %s [OPTIONS] [--] <command> [args...]\n", prog_name);
  fprintf(stderr, "Options:\n");
  fprintf(stderr,
          "  --help                  Show this help message and exit\n");
  fprintf(stderr,
          "  --version               Show version information and exit\n");
  fprintf(stderr, "  --engine=<type>         Select sandbox engine (native, "
                  "docker, podman, gvisor, wasmtime, appcontainer, "
                  "dummy [default])\n");
  fprintf(stderr, "  --no-network            Disable network access\n");
  fprintf(stderr, "  --env=KEY=VALUE         Set environment variable\n");
  fprintf(stderr, "  --mount=DIR             Mount a directory (read-write)\n");
  fprintf(stderr, "  --ro-mount=DIR          Mount a directory (read-only)\n");
  fprintf(stderr,
          "  --timeout=SECS          Set execution timeout in seconds\n");
  fprintf(stderr, "  --memory-mb=MB          Set memory limit in MB\n");
  fprintf(stderr, "  --cpu-pct=PCT           Set CPU limit in percentage\n");
  fprintf(stderr, "  --drop-privs            Drop privileges\n");
  fprintf(stderr,
          "  --uid=UID               Set target UID (implies --drop-privs)\n");
  fprintf(stderr,
          "  --gid=GID               Set target GID (implies --drop-privs)\n");
  fprintf(stderr, "  --deny-syscall=SYSCALL  Deny specific syscall\n");
  fprintf(stderr, "\n");
  fprintf(stderr,
          "Use '--' before <command> to ensure subsequent arguments are "
          "treated as command arguments rather than sandbox options.\n");
  fprintf(stderr, "\n");
  fprintf(stderr,
          "Example: %s --engine=native --drop-privs --deny-syscall=ptrace "
          "--mount=/tmp -- curl http://google.com\n",
          prog_name);
  return SANDBOX_SUCCESS;
}

#if defined(SANDBOX_ENABLE_MOCKS)
/** \brief Flag to force safe_getenv to fail during fault-injection tests. */
int g_sandbox_mock_getenv_fail = 0;
#endif

/**
 * \brief Safely retrieves an environment variable.
 * \param name The name of the environment variable.
 * \param out_value Pointer to receive the string value.
 * \return SANDBOX_SUCCESS on success, or SANDBOX_ERR_INVALID_ARG on error.
 */
static sandbox_error_t safe_getenv(const char *name, const char **out_value) {
  if (!name || !out_value) {
    return SANDBOX_ERR_INVALID_ARG;
  }
#if defined(SANDBOX_ENABLE_MOCKS)
  if (g_sandbox_mock_getenv_fail) {
    *out_value = NULL;
    return SANDBOX_ERR_IO;
  }
#endif
#if defined(_MSC_VER)
  {
    static char env_bufs[12][512];
    static int env_buf_idx = 0;
    char *value = NULL;
    size_t size = 0;
    if (_dupenv_s(&value, &size, name) != 0 || !value || value[0] == '\0') {
      if (value) {
        free(value);
      }
      *out_value = NULL;
      return SANDBOX_SUCCESS;
    }
    strcpy_s(env_bufs[env_buf_idx], sizeof(env_bufs[0]), value);
    free(value);
    *out_value = env_bufs[env_buf_idx];
    env_buf_idx = (env_buf_idx + 1) % 12;
  }
#else
  *out_value = getenv(name);
#endif
  return SANDBOX_SUCCESS;
}

/**
 * \brief Counts occurrences of a character in a string.
 * \param s The string to search.
 * \param c The character to count.
 * \param out Pointer to receive the count.
 * \return SANDBOX_SUCCESS on success, or SANDBOX_ERR_INVALID_ARG on error.
 */
#if defined(SANDBOX_ENABLE_MOCKS)
int g_sandbox_mock_count_char_fail = 0;
#endif

static sandbox_error_t count_char(const char *s, char c, int *out) {
  int count = 0;
  if (!out) {
    return SANDBOX_ERR_INVALID_ARG;
  }
#if defined(SANDBOX_ENABLE_MOCKS)
  if (g_sandbox_mock_count_char_fail) {
    return SANDBOX_ERR_INVALID_ARG;
  }
#endif
  if (!s) {
    *out = 0;
    return SANDBOX_SUCCESS;
  }
  while (*s) {
    if (*s == c) {
      count++;
    }
    s++;
  }
  *out = count;
  return SANDBOX_SUCCESS;
}

/**
 * \brief Duplicates a string using malloc.
 * \param s The string to duplicate.
 * \param out Pointer to receive the duplicated string.
 * \return SANDBOX_SUCCESS on success, or an error enum on failure.
 */
static sandbox_error_t my_strdup(const char *s, char **out) {
  sandbox_error_t rc;
  size_t len;
  void *raw_d = NULL;
  char *d;
  if (!s || !out) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  len = strlen(s);
  rc = sandbox_alloc(len + 1, &raw_d);
  if (rc != SANDBOX_SUCCESS) {
    *out = NULL;
    return rc;
  }
  d = (char *)raw_d;
#if defined(_MSC_VER)
  strcpy_s(d, len + 1, s);
#else
  strcpy(d, s);
#endif
  *out = d;
  return SANDBOX_SUCCESS;
}

/**
 * \brief Splits a string by a separator and appends parts to an array.
 * \param str The string to split.
 * \param sep The separator character.
 * \param array The array to append to.
 * \param count Pointer to the current count, updated upon success.
 * \param out_copy Pointer to store the allocated backing buffer for cleanup.
 * \return SANDBOX_SUCCESS on success, or an error enum on failure.
 */
static sandbox_error_t split_and_append(const char *str, char sep,
                                        const char **array, size_t *count,
                                        char **out_copy) {
  sandbox_error_t rc;
  char *copy = NULL;
  char *p;
  char *start;
  if (!array || !count || !out_copy) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  *out_copy = NULL;
  if (!str) {
    return SANDBOX_SUCCESS;
  }
  rc = my_strdup(str, &copy);
  if (rc != SANDBOX_SUCCESS) {
    return rc;
  }
  *out_copy = copy;
  start = copy;
  while ((p = strchr(start, sep)) != NULL) {
    *p = '\0';
    array[(*count)++] = start;
    start = p + 1;
  }
  if (*start != '\0') {
    array[(*count)++] = start;
  }
  return SANDBOX_SUCCESS;
}

/**
 * \brief Splits a string by a separator and appends mounts to an array.
 * \param str The string to split.
 * \param sep The separator character.
 * \param read_only Flag indicating if mounts are read-only.
 * \param array The array of sandbox_mount_t to append to.
 * \param count Pointer to the current count, updated upon success.
 * \param out_copy Pointer to store the allocated backing buffer for cleanup.
 * \return SANDBOX_SUCCESS on success, or an error enum on failure.
 */
static sandbox_error_t split_and_append_mount(const char *str, char sep,
                                              int read_only,
                                              sandbox_mount_t *array,
                                              size_t *count, char **out_copy) {
  sandbox_error_t rc;
  char *copy = NULL;
  char *p;
  char *start;
  if (!array || !count || !out_copy) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  *out_copy = NULL;
  if (!str) {
    return SANDBOX_SUCCESS;
  }
  rc = my_strdup(str, &copy);
  if (rc != SANDBOX_SUCCESS) {
    return rc;
  }
  *out_copy = copy;
  start = copy;
  while ((p = strchr(start, sep)) != NULL) {
    *p = '\0';
    array[*count].dir = start;
    array[*count].read_only = read_only;
    (*count)++;
    start = p + 1;
  }
  if (*start != '\0') {
    array[*count].dir = start;
    array[*count].read_only = read_only;
    (*count)++;
  }
  return SANDBOX_SUCCESS;
}

/**
 * \brief Runs the CLI argument parser and executes the requested sandbox
 * command.
 * \param argc Argument count.
 * \param argv Argument vector.
 * \param out_exit_code Pointer to store the resulting process exit code.
 * \return SANDBOX_SUCCESS on success, or an error enum on failure.
 */
static sandbox_error_t sandbox_cli_run(int argc, char **argv,
                                       int *out_exit_code) {
  sandbox_error_t rc = SANDBOX_SUCCESS;
  void *raw_ptr = NULL;
  int i;
  int cmd_start_idx = 1;
  int status = 0;
  const char *engine_name = "dummy";
  sandbox_engine_t *engine = NULL;
  sandbox_config_t config;
  const char **env_vars_buf = NULL;
  size_t env_count = 0;
  sandbox_mount_t *mounts_buf = NULL;
  size_t mount_count = 0;
  const char **syscalls_buf = NULL;
  size_t syscall_count = 0;
  char *copy_env = NULL;
  char *copy_mount = NULL;
  char *copy_ro_mount = NULL;
  char *copy_deny_syscall = NULL;

  const char *env_vals[12];
  static const char *const env_names[12] = {
      "MOUNTSANDBOX_ENGINE",     "MOUNTSANDBOX_NO_NETWORK",
      "MOUNTSANDBOX_ENV",        "MOUNTSANDBOX_MOUNT",
      "MOUNTSANDBOX_RO_MOUNT",   "MOUNTSANDBOX_TIMEOUT",
      "MOUNTSANDBOX_MEMORY_MB",  "MOUNTSANDBOX_CPU_PCT",
      "MOUNTSANDBOX_DROP_PRIVS", "MOUNTSANDBOX_UID",
      "MOUNTSANDBOX_GID",        "MOUNTSANDBOX_DENY_SYSCALL"};
  int extra_envs = 0;
  int extra_mounts = 0;
  int extra_syscalls = 0;

  if (!argv || !out_exit_code) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  *out_exit_code = EXIT_FAILURE;

  if (argc < 2) {
    rc = print_usage(argc > 0 ? argv[0] : NULL);
    if (rc != SANDBOX_SUCCESS) {
      return rc;
    }
    return SANDBOX_ERR_INVALID_ARG;
  }

  for (i = 0; i < 12; i++) {
    env_vals[i] = NULL;
    rc = safe_getenv(env_names[i], &env_vals[i]);
    if (rc != SANDBOX_SUCCESS) {
      return rc;
    }
  }

  {
    int list_indices[4];
    int list_counts[4];
    list_indices[0] = 2;
    list_indices[1] = 3;
    list_indices[2] = 4;
    list_indices[3] = 11;
    for (i = 0; i < 4; i++) {
      list_counts[i] = 0;
      if (env_vals[list_indices[i]]) {
        rc = count_char(env_vals[list_indices[i]], ',', &list_counts[i]);
        if (rc != SANDBOX_SUCCESS) {
          return rc;
        }
        list_counts[i]++;
      }
    }
    extra_envs = list_counts[0];
    extra_mounts = list_counts[1] + list_counts[2];
    extra_syscalls = list_counts[3];
  }

  memset(&config, 0, sizeof(config));

  rc = sandbox_alloc((size_t)(argc + extra_envs) * sizeof(const char *),
                     &raw_ptr);
  if (rc != SANDBOX_SUCCESS) {
    fputs("Error: out of memory\x0a", stderr);
    goto cleanup;
  }
  env_vars_buf = (const char **)raw_ptr;

  rc = sandbox_alloc(
      (size_t)(argc + extra_mounts + 1) * sizeof(sandbox_mount_t), &raw_ptr);
  if (rc != SANDBOX_SUCCESS) {
    fputs("Error: out of memory\x0a", stderr);
    goto cleanup;
  }
  mounts_buf = (sandbox_mount_t *)raw_ptr;

  rc = sandbox_alloc((size_t)(argc + extra_syscalls) * sizeof(const char *),
                     &raw_ptr);
  if (rc != SANDBOX_SUCCESS) {
    fputs("Error: out of memory\x0a", stderr);
    goto cleanup;
  }
  syscalls_buf = (const char **)raw_ptr;

  if (env_vals[0]) {
    engine_name = env_vals[0];
  }
  if (env_vals[1] && strcmp(env_vals[1], "0") != 0 &&
      strcmp(env_vals[1], "false") != 0) {
    config.disable_network = 1;
  }
  if (env_vals[5]) {
    config.timeout_secs = (unsigned int)atoi(env_vals[5]);
  }
  if (env_vals[6]) {
    config.max_memory_mb = (unsigned int)atoi(env_vals[6]);
  }
  if (env_vals[7]) {
    config.max_cpu_percent = (unsigned int)atoi(env_vals[7]);
  }
  if (env_vals[8] && strcmp(env_vals[8], "0") != 0 &&
      strcmp(env_vals[8], "false") != 0) {
    config.drop_privileges = 1;
  }
  if (env_vals[9]) {
    config.drop_privileges = 1;
    config.target_uid = (unsigned int)atoi(env_vals[9]);
  }
  if (env_vals[10]) {
    config.drop_privileges = 1;
    config.target_gid = (unsigned int)atoi(env_vals[10]);
  }

  rc = split_and_append(env_vals[2], ',', env_vars_buf, &env_count, &copy_env);
  if (rc != SANDBOX_SUCCESS) {
    goto cleanup;
  }
  rc = split_and_append_mount(env_vals[3], ',', 0, mounts_buf, &mount_count,
                              &copy_mount);
  if (rc != SANDBOX_SUCCESS) {
    goto cleanup;
  }
  rc = split_and_append_mount(env_vals[4], ',', 1, mounts_buf, &mount_count,
                              &copy_ro_mount);
  if (rc != SANDBOX_SUCCESS) {
    goto cleanup;
  }
  rc = split_and_append(env_vals[11], ',', syscalls_buf, &syscall_count,
                        &copy_deny_syscall);
  if (rc != SANDBOX_SUCCESS) {
    goto cleanup;
  }

  while (cmd_start_idx < argc && strncmp(argv[cmd_start_idx], "--", 2) == 0) {
    if (strcmp(argv[cmd_start_idx], "--help") == 0) {
      *out_exit_code = EXIT_SUCCESS;
      rc = print_usage(argv[0]);
      if (rc != SANDBOX_SUCCESS) {
        goto cleanup;
      }
      goto cleanup;
    } else if (strcmp(argv[cmd_start_idx], "--version") == 0) {
      *out_exit_code = EXIT_SUCCESS;
      rc = print_version();
      if (rc != SANDBOX_SUCCESS) {
        goto cleanup;
      }
      goto cleanup;
    } else if (strcmp(argv[cmd_start_idx], "--") == 0) {
      cmd_start_idx++;
      break;
    } else if (strncmp(argv[cmd_start_idx], "--engine=", 9) == 0) {
      engine_name = argv[cmd_start_idx] + 9;
    } else if (strcmp(argv[cmd_start_idx], "--no-network") == 0) {
      config.disable_network = 1;
    } else if (strncmp(argv[cmd_start_idx], "--env=", 6) == 0) {
      env_vars_buf[env_count++] = argv[cmd_start_idx] + 6;
    } else if (strncmp(argv[cmd_start_idx], "--mount=", 8) == 0) {
      mounts_buf[mount_count].dir = argv[cmd_start_idx] + 8;
      mounts_buf[mount_count].read_only = 0;
      mount_count++;
    } else if (strncmp(argv[cmd_start_idx], "--ro-mount=", 11) == 0) {
      mounts_buf[mount_count].dir = argv[cmd_start_idx] + 11;
      mounts_buf[mount_count].read_only = 1;
      mount_count++;
    } else if (strncmp(argv[cmd_start_idx], "--timeout=", 10) == 0) {
      config.timeout_secs = (unsigned int)atoi(argv[cmd_start_idx] + 10);
    } else if (strncmp(argv[cmd_start_idx], "--memory-mb=", 12) == 0) {
      config.max_memory_mb = (unsigned int)atoi(argv[cmd_start_idx] + 12);
    } else if (strncmp(argv[cmd_start_idx], "--cpu-pct=", 10) == 0) {
      config.max_cpu_percent = (unsigned int)atoi(argv[cmd_start_idx] + 10);
    } else if (strcmp(argv[cmd_start_idx], "--drop-privs") == 0) {
      config.drop_privileges = 1;
    } else if (strncmp(argv[cmd_start_idx], "--uid=", 6) == 0) {
      config.drop_privileges = 1;
      config.target_uid = (unsigned int)atoi(argv[cmd_start_idx] + 6);
    } else if (strncmp(argv[cmd_start_idx], "--gid=", 6) == 0) {
      config.drop_privileges = 1;
      config.target_gid = (unsigned int)atoi(argv[cmd_start_idx] + 6);
    } else if (strncmp(argv[cmd_start_idx], "--deny-syscall=", 15) == 0) {
      syscalls_buf[syscall_count++] = argv[cmd_start_idx] + 15;
    } else {
      fprintf(stderr, "Error: Unknown flag '%s'\n", argv[cmd_start_idx]);
      rc = print_usage(argv[0]);
      if (rc != SANDBOX_SUCCESS) {
        goto cleanup;
      }
      rc = SANDBOX_ERR_INVALID_ARG;
      goto cleanup;
    }
    cmd_start_idx++;
  }

  if (mount_count == 0) {
    mounts_buf[mount_count].dir = ".";
    mounts_buf[mount_count].read_only = 0;
    mount_count++;
  }

  config.env_vars = env_vars_buf;
  config.env_count = env_count;
  config.mounts = mounts_buf;
  config.mount_count = mount_count;
  config.denied_syscalls = syscalls_buf;
  config.denied_syscall_count = syscall_count;

  if (cmd_start_idx >= argc) {
    fprintf(stderr, "Error: No command provided.\n");
    rc = print_usage(argv[0]);
    if (rc != SANDBOX_SUCCESS) {
      goto cleanup;
    }
    rc = SANDBOX_ERR_INVALID_ARG;
    goto cleanup;
  }

  printf("[libmountsandbox] Selected Engine: %s\n", engine_name);
  if (config.disable_network) {
    printf("[libmountsandbox] Network access is disabled.\n");
  }
  for (i = 0; i < (int)config.mount_count; i++) {
    printf("[libmountsandbox] Mount: %s (%s)\n", config.mounts[i].dir,
           config.mounts[i].read_only ? "ro" : "rw");
  }
  for (i = 0; i < (int)config.env_count; i++) {
    printf("[libmountsandbox] Environment: %s\n", config.env_vars[i]);
  }

  rc = get_sandbox_engine(engine_name, &engine);
  if (rc != SANDBOX_SUCCESS) {
    fprintf(stderr, "Error: Unknown engine '%s'\n", engine_name);
    goto cleanup;
  }

  rc = engine->init();
  if (rc != SANDBOX_SUCCESS) {
    fprintf(stderr, "Error: Failed to initialize engine '%s'\n", engine_name);
    goto cleanup;
  }

  printf("[libmountsandbox] Executing command: ");
  for (i = cmd_start_idx; i < argc; i++) {
    printf("%s ", argv[i]);
  }
  printf("\n");

  rc = engine->execute(&config, argc - cmd_start_idx, &argv[cmd_start_idx],
                       &status);
  if (rc != SANDBOX_SUCCESS) {
    fprintf(stderr, "[libmountsandbox] Execution failed with error %d\n",
            (int)rc);
    goto cleanup;
  }

  rc = engine->cleanup();
  if (rc != SANDBOX_SUCCESS) {
    goto cleanup;
  }

  if (status != 0) {
    fprintf(stderr, "[libmountsandbox] Command exited with status %d\n",
            status);
    *out_exit_code = status > 0 ? status : EXIT_FAILURE;
    goto cleanup;
  }

  *out_exit_code = EXIT_SUCCESS;

cleanup:
  if (copy_env) {
    free(copy_env);
  }
  if (copy_mount) {
    free(copy_mount);
  }
  if (copy_ro_mount) {
    free(copy_ro_mount);
  }
  if (copy_deny_syscall) {
    free(copy_deny_syscall);
  }
  if (env_vars_buf) {
    free(env_vars_buf);
  }
  if (mounts_buf) {
    free(mounts_buf);
  }
  if (syscalls_buf) {
    free(syscalls_buf);
  }
  return rc;
}

#ifndef SANDBOX_TESTING_MAIN
/**
 * \brief Main entry point for the mountsandbox CLI.
 * \param argc Argument count.
 * \param argv Argument vector.
 * \return EXIT_SUCCESS on success, or non-zero exit status on error.
 */
int main(int argc, char **argv) {
  int exit_code = EXIT_FAILURE;
  sandbox_error_t rc;
  rc = sandbox_cli_run(argc, argv, &exit_code);
  if (rc != SANDBOX_SUCCESS) {
    return EXIT_FAILURE;
  }
  return exit_code;
}
#endif
