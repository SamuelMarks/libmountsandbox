/**
 * \file main.c
 * \brief Command-line interface for libmountsandbox.
 */
/* clang-format off */
#include "sandbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* clang-format on */
void print_usage(const char *prog_name);
void print_version(void);

/**
 * \brief Prints the version information.
 */
void print_version(void) { printf("libmountsandbox version 0.1.0\n"); }

/**
 * \brief Prints the usage information.
 * \param prog_name The name of the program executable.
 */
void print_usage(const char *prog_name) {
  fprintf(stderr, "Usage: %s [OPTIONS] [--] <command> [args...]\n", prog_name);
  fprintf(stderr, "Options:\n");
  fprintf(stderr,
          "  --help                  Show this help message and exit\n");
  fprintf(stderr,
          "  --version               Show version information and exit\n");
  fprintf(stderr, "  --engine=<type>         Select sandbox engine (docker, "
                  "dummy, native [default])\n");
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
}

/**
 * \brief Safely retrieves an environment variable.
 * \param name The name of the environment variable.
 * \param out_value Pointer to receive the string value.
 * \return 0 on success, or -1 on error.
 */
static int safe_getenv(const char *name, const char **out_value) {
  if (!name || !out_value)
    return -1;
#if defined(_MSC_VER)
  {
    char *value = NULL;
    size_t size = 0;
    _dupenv_s(&value, &size, name);
    *out_value = value;
  }
#else
  *out_value = getenv(name);
#endif
  return 0;
}

/**
 * \brief Counts occurrences of a character in a string.
 * \param s The string to search.
 * \param c The character to count.
 * \param out Pointer to receive the count.
 * \return 0 on success, or -1 on error.
 */
static int count_char(const char *s, char c, int *out) {
  int count = 0;
  if (!s || !out)
    return -1;
  while (*s) {
    if (*s == c)
      count++;
    s++;
  }
  *out = count;
  return 0;
}

/**
 * \brief Duplicates a string using malloc.
 * \param s The string to duplicate.
 * \param out Pointer to receive the duplicated string.
 * \return 0 on success, or -1 on error.
 */
static int my_strdup(const char *s, char **out) {
  size_t len;
  char *d;
  if (!s || !out)
    return -1;
  len = strlen(s);
  d = (char *)malloc(len + 1);
  if (!d)
    return -1;
#if defined(_MSC_VER)
  strcpy_s(d, len + 1, s);
#else
  strcpy(d, s);
#endif
  *out = d;
  return 0;
}

/**
 * \brief Splits a string by a separator and appends parts to an array.
 * \param str The string to split.
 * \param sep The separator character.
 * \param array The array to append to.
 * \param count Pointer to the current count, updated upon success.
 * \return 0 on success, or -1 on error.
 */
static int split_and_append(const char *str, char sep, const char **array,
                            size_t *count) {
  char *copy = NULL;
  char *p, *start;
  if (!str)
    return 0;
  if (my_strdup(str, &copy) != 0)
    return -1;
  start = copy;
  while ((p = strchr(start, sep)) != NULL) {
    *p = '\0';
    array[(*count)++] = start;
    start = p + 1;
  }
  if (*start != '\0') {
    array[(*count)++] = start;
  }
  return 0;
}

/**
 * \brief Splits a string by a separator and appends mounts to an array.
 * \param str The string to split.
 * \param sep The separator character.
 * \param read_only Flag indicating if mounts are read-only.
 * \param array The array of sandbox_mount_t to append to.
 * \param count Pointer to the current count, updated upon success.
 * \return 0 on success, or -1 on error.
 */
static int split_and_append_mount(const char *str, char sep, int read_only,
                                  sandbox_mount_t *array, size_t *count) {
  char *copy = NULL;
  char *p, *start;
  if (!str)
    return 0;
  if (my_strdup(str, &copy) != 0)
    return -1;
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
  return 0;
}

/**
 * \brief Main entry point for the mountsandbox CLI.
 * \param argc Argument count.
 * \param argv Argument vector.
 * \return EXIT_SUCCESS on success, or EXIT_FAILURE on error.
 */
int main(int argc, char **argv) {
  int i;
  int cmd_start_idx = 1;
  int status;
  const char *engine_name = "dummy"; /* Default engine */
  sandbox_engine_t *engine = NULL;
  sandbox_config_t config;
  const char **env_vars_buf = NULL;
  size_t env_count = 0;
  sandbox_mount_t *mounts_buf = NULL;
  size_t mount_count = 0;
  const char **syscalls_buf = NULL;
  size_t syscall_count = 0;

  const char *env_engine = NULL;
  const char *env_no_network = NULL;
  const char *env_env = NULL;
  const char *env_mount = NULL;
  const char *env_ro_mount = NULL;
  const char *env_timeout = NULL;
  const char *env_memory_mb = NULL;
  const char *env_cpu_pct = NULL;
  const char *env_drop_privs = NULL;
  const char *env_uid = NULL;
  const char *env_gid = NULL;
  const char *env_deny_syscall = NULL;
  int extra_envs = 0, extra_mounts = 0, extra_syscalls = 0;

  safe_getenv("MOUNTSANDBOX_ENGINE", &env_engine);
  safe_getenv("MOUNTSANDBOX_NO_NETWORK", &env_no_network);
  safe_getenv("MOUNTSANDBOX_ENV", &env_env);
  safe_getenv("MOUNTSANDBOX_MOUNT", &env_mount);
  safe_getenv("MOUNTSANDBOX_RO_MOUNT", &env_ro_mount);
  safe_getenv("MOUNTSANDBOX_TIMEOUT", &env_timeout);
  safe_getenv("MOUNTSANDBOX_MEMORY_MB", &env_memory_mb);
  safe_getenv("MOUNTSANDBOX_CPU_PCT", &env_cpu_pct);
  safe_getenv("MOUNTSANDBOX_DROP_PRIVS", &env_drop_privs);
  safe_getenv("MOUNTSANDBOX_UID", &env_uid);
  safe_getenv("MOUNTSANDBOX_GID", &env_gid);
  safe_getenv("MOUNTSANDBOX_DENY_SYSCALL", &env_deny_syscall);

  if (env_env) {
    count_char(env_env, ',', &extra_envs);
    extra_envs++;
  }
  if (env_mount) {
    int n = 0;
    count_char(env_mount, ',', &n);
    extra_mounts += n + 1;
  }
  if (env_ro_mount) {
    int n = 0;
    count_char(env_ro_mount, ',', &n);
    extra_mounts += n + 1;
  }
  if (env_deny_syscall) {
    count_char(env_deny_syscall, ',', &extra_syscalls);
    extra_syscalls++;
  }
  config.disable_network = 0;
  config.timeout_secs = 0;
  config.stdout_buffer = NULL;
  config.stdout_size = NULL;
  config.stderr_buffer = NULL;
  config.stderr_size = NULL;
  config.max_memory_mb = 0;
  config.max_cpu_percent = 0;
  config.drop_privileges = 0;
  config.target_uid = 0;
  config.target_gid = 0;
  config.denied_syscalls = NULL;
  config.denied_syscall_count = 0;

  if (argc < 2) {
    print_usage(argv[0]);
    return EXIT_FAILURE;
  }

  env_vars_buf =
      (const char **)malloc((size_t)(argc + extra_envs) * sizeof(const char *));
  mounts_buf = (sandbox_mount_t *)malloc((size_t)(argc + extra_mounts + 1) *
                                         sizeof(sandbox_mount_t));
  syscalls_buf = (const char **)malloc((size_t)(argc + extra_syscalls) *
                                       sizeof(const char *));
  if (!env_vars_buf || !mounts_buf || !syscalls_buf) {
    fprintf(stderr, "Error: out of memory\n");
    if (env_vars_buf)
      free((void *)env_vars_buf);
    if (mounts_buf)
      free((void *)mounts_buf);
    if (syscalls_buf)
      free((void *)syscalls_buf);
    return EXIT_FAILURE;
  }

  /* Apply environment variables first */
  if (env_engine) {
    engine_name = env_engine;
  }
  if (env_no_network && strcmp(env_no_network, "0") != 0 &&
      strcmp(env_no_network, "false") != 0) {
    config.disable_network = 1;
  }
  if (env_timeout) {
    config.timeout_secs = (unsigned int)atoi(env_timeout);
  }
  if (env_memory_mb) {
    config.max_memory_mb = (unsigned int)atoi(env_memory_mb);
  }
  if (env_cpu_pct) {
    config.max_cpu_percent = (unsigned int)atoi(env_cpu_pct);
  }
  if (env_drop_privs && strcmp(env_drop_privs, "0") != 0 &&
      strcmp(env_drop_privs, "false") != 0) {
    config.drop_privileges = 1;
  }
  if (env_uid) {
    config.drop_privileges = 1;
    config.target_uid = (unsigned int)atoi(env_uid);
  }
  if (env_gid) {
    config.drop_privileges = 1;
    config.target_gid = (unsigned int)atoi(env_gid);
  }

  if (env_env && split_and_append(env_env, ',', env_vars_buf, &env_count) != 0)
    return EXIT_FAILURE;
  if (env_mount &&
      split_and_append_mount(env_mount, ',', 0, mounts_buf, &mount_count) != 0)
    return EXIT_FAILURE;
  if (env_ro_mount && split_and_append_mount(env_ro_mount, ',', 1, mounts_buf,
                                             &mount_count) != 0)
    return EXIT_FAILURE;
  if (env_deny_syscall && split_and_append(env_deny_syscall, ',', syscalls_buf,
                                           &syscall_count) != 0)
    return EXIT_FAILURE;

  /* Parse basic arguments, CLI overrides ENV */
  while (cmd_start_idx < argc && strncmp(argv[cmd_start_idx], "--", 2) == 0) {
    if (strcmp(argv[cmd_start_idx], "--help") == 0) {
      print_usage(argv[0]);
      free((void *)env_vars_buf);
      free((void *)mounts_buf);
      free((void *)syscalls_buf);
      return EXIT_SUCCESS;
    } else if (strcmp(argv[cmd_start_idx], "--version") == 0) {
      print_version();
      free((void *)env_vars_buf);
      free((void *)mounts_buf);
      free((void *)syscalls_buf);
      return EXIT_SUCCESS;
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
      print_usage(argv[0]);
      free((void *)env_vars_buf);
      free((void *)mounts_buf);
      free((void *)syscalls_buf);
      return EXIT_FAILURE;
    }
    cmd_start_idx++;
  }

  /* Provide a default mount if none specified */
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
    print_usage(argv[0]);
    free((void *)env_vars_buf);
    free((void *)mounts_buf);
    free((void *)syscalls_buf);
    return EXIT_FAILURE;
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

  if (get_sandbox_engine(engine_name, &engine) != 0 || !engine) {
    fprintf(stderr, "Error: Unknown engine '%s'\n", engine_name);
    free((void *)env_vars_buf);
    free((void *)mounts_buf);
    free((void *)syscalls_buf);
    return EXIT_FAILURE;
  }

  if (engine->init() != 0) {
    fprintf(stderr, "Error: Failed to initialize engine '%s'\n", engine_name);
    free((void *)env_vars_buf);
    free((void *)mounts_buf);
    free((void *)syscalls_buf);
    return EXIT_FAILURE;
  }

  printf("[libmountsandbox] Executing command: ");
  for (i = cmd_start_idx; i < argc; i++) {
    printf("%s ", argv[i]);
  }
  printf("\n");

  /* Execute the sub-command via the selected engine */
  status = engine->execute(&config, argc - cmd_start_idx, &argv[cmd_start_idx]);

  engine->cleanup();
  free((void *)env_vars_buf);
  free((void *)mounts_buf);
  free((void *)syscalls_buf);

  if (status != 0) {
    fprintf(stderr, "[libmountsandbox] Command exited with status %d\n",
            status);
    return status > 0 ? status : EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}
