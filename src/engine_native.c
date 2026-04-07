#if defined(__APPLE__) || defined(__linux__) || defined(__CYGWIN__)
#define _XOPEN_SOURCE 600
#endif
#define _WIN32_WINNT 0x0600
/**
 * \file engine_native.c
 * \brief Native OS sandbox implementation.
 *
 * This engine maps the execution of a command into a native OS sandboxing
 * facility (e.g., sandbox-exec on macOS, bwrap/namespaces on Linux).
 */
/* clang-format off */
#include "sandbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#if defined(__APPLE__) || defined(__linux__)
#include <signal.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <sys/param.h>
#endif

#if defined(__linux__)
#include <limits.h>
#endif

#if defined(_WIN32)
#include <io.h>
#include <winsock2.h>
#endif
/* clang-format on */

#if defined(__linux__) || defined(__APPLE__) || defined(_WIN32)
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
#endif

#if defined(__APPLE__) || defined(__linux__)
#define _XOPEN_SOURCE 600
#endif

#if defined(__APPLE__)
/* ========================================================================= */
/* macOS App Sandbox (sandbox-exec) Implementation                           */
/* ========================================================================= */

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

/**
 * \brief Initializes the engine.
 * \return 0 on success, or -1 on error.
 */
static int native_init(void) {
  /* sandbox-exec is natively available on macOS */
  return 0;
}

/**
 * \brief Executes a command in the sandbox synchronously.
 * \param config Sandbox configuration.
 * \param argc Argument count.
 * \param argv Argument vector.
 * \return Exit status, or -1 on error.
 */
static int native_execute(const sandbox_config_t *config, int argc,
                          char **argv) {
  char **exec_argv;
  int i, status = -1;
  char abs_path[PATH_MAX];
  char *profile;
  pid_t pid;
  int master_fd = -1;
  size_t profile_len;
  FILE *out_fp = NULL;
  FILE *err_fp = NULL;

  const char *profile_template_base =
      "(version 1)\n"
      "(allow default)\n"
      "(deny file-write*)\n"
      "(allow file-write* (subpath \"/dev\"))\n"
      "(allow file-write* (subpath \"/private/tmp\"))\n"
      "(allow file-write* (subpath \"/var/folders\"))\n";

  const char *profile_network_deny = (char *)"(deny network*)\n";

  if (!config || !argv)
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

  profile_len = strlen(profile_template_base) + 1;
  if (config->use_pty) {
    fprintf(stderr,
            "[libmountsandbox] Warning: Interactive PTY is not natively "
            "supported on Windows Job Objects without ConPTY. Ignored.\n");
  }
  if (config->disable_network) {
    profile_len += strlen(profile_network_deny);
  }

  if (config->seccomp_profile_path || config->apparmor_profile) {
    fprintf(stderr, "[libmountsandbox] Warning: Seccomp/AppArmor profiles are "
                    "not natively supported on macOS. Ignored.\n");
  }
  if (config->seccomp_profile_path || config->apparmor_profile) {
    fprintf(stderr,
            "[libmountsandbox] Warning: Seccomp/AppArmor profiles are not "
            "natively supported via Windows Job Objects. Ignored.\n");
  }
  if (config->denied_syscalls && config->denied_syscall_count > 0) {
    size_t c;
    for (c = 0; c < config->denied_syscall_count; c++) {
      /* (deny system-mac-syscall (mac-syscall-number 0)) is seatbelt but we use
       * simple deny process-exec or similar approximate mappings since true
       * syscall filtering in Seatbelt requires precise private API macros. We
       * emit a warning. */
    }
    fprintf(stderr, "[libmountsandbox] Warning: Fine-grained syscall filtering "
                    "is not supported natively via macOS Seatbelt. Ignored.\n");
  }

  if (config->mounts) {
    size_t m;
    for (m = 0; m < config->mount_count; m++) {
      if (realpath(config->mounts[m].dir, abs_path) != NULL) {
        if (!config->mounts[m].read_only) {
          /* (allow file-write* (subpath "abs_path"))\n */
          profile_len += 33 + strlen(abs_path) + 4;
        }
      }
    }
  }

  profile = (char *)malloc((size_t)profile_len);
  if (!profile) {
    return -1;
  }

#if defined(_MSC_VER)
  strcpy_s(profile, profile_len, profile_template_base);
#else
  strcpy(profile, profile_template_base);
#endif
  if (config->disable_network) {
#if defined(_MSC_VER)
    strcat_s(profile, sizeof(profile), profile_network_deny);
#else
    strcat(profile, profile_network_deny);
#endif
  }

  if (config->mounts) {
    size_t m;
    for (m = 0; m < config->mount_count; m++) {
      if (realpath(config->mounts[m].dir, abs_path) != NULL) {
        if (!config->mounts[m].read_only) {
#if defined(_MSC_VER)
          strcat_s(profile, sizeof(profile), "(allow file-write* (subpath \"");
#else
          strcat(profile, "(allow file-write* (subpath \"");
#endif
#if defined(_MSC_VER)
          strcat_s(profile, sizeof(profile), abs_path);
#else
          strcat(profile, abs_path);
#endif
#if defined(_MSC_VER)
          strcat_s(profile, sizeof(profile), "\"))\n");
#else
          strcat(profile, "\"))\n");
#endif
        }
      }
    }
  }

  exec_argv = (char **)malloc((size_t)(argc + 4) * sizeof(char *));
  if (!exec_argv) {
    free(profile);
    return -1;
  }

  exec_argv[0] = (char *)"sandbox-exec";
  exec_argv[1] = (char *)"-p";
  exec_argv[2] = profile;
  for (i = 0; i < argc; i++) {
    exec_argv[3 + i] = argv[i];
  }
  exec_argv[3 + argc] = NULL;

  if (config->use_pty) {
    master_fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (master_fd >= 0) {
      grantpt(master_fd);
      unlockpt(master_fd);
    } else {
      perror("[libmountsandbox] posix_openpt failed");
    }
  }

  pid = fork();
  if (pid < 0) {
    status = -1;
  } else if (pid == 0) {
    /* Child process */
    if (config->seccomp_profile_path) {
      int i;
      FILE *sfp = fopen(config->seccomp_profile_path, "r");
      if (!sfp) {
        perror("[libmountsandbox] Failed to open seccomp profile");
        exit(127);
      }
      for (i = 0; exec_argv[i] != NULL; i++) {
        if (strcmp(exec_argv[i], "_SECCOMP_FD_") == 0) {
          char fd_str[32];
#if defined(_MSC_VER)
          sprintf_s(fd_str, sizeof(fd_str), "%d", fileno(sfp));
#else
          sprintf(fd_str, "%d", fileno(sfp));
#endif
          exec_argv[i] = strdup(fd_str);
          break;
        }
      }
    }
    if (config->apparmor_profile) {
      FILE *afp = fopen("/proc/self/attr/exec", "w");
      if (afp) {
        fprintf(afp, "exec %s", config->apparmor_profile);
        fclose(afp);
      } else {
        fprintf(stderr, "[libmountsandbox] Warning: Could not open "
                        "/proc/self/attr/exec to set AppArmor profile\n");
      }
    }
    if (config->env_vars && config->env_count > 0) {
      size_t e;
      for (e = 0; e < config->env_count; e++) {
        putenv((char *)config->env_vars[e]);
      }
    }
    if (config->use_pty && master_fd >= 0) {
      char *slave_name = ptsname(master_fd);
      int slave_fd = open(slave_name, O_RDWR);
      setsid();
#if defined(__APPLE__)
      /* macOS setsid creates a new session but TIOCSCTTY is not standard,
       * login_tty is better but open handles it on macOS if O_NOCTTY is not
       * used */
#endif
      dup2(slave_fd, STDIN_FILENO);
      dup2(slave_fd, STDOUT_FILENO);
      dup2(slave_fd, STDERR_FILENO);
      close(slave_fd);
      close(master_fd);
    } else {
      if (out_fp)
        dup2(fileno(out_fp), STDOUT_FILENO);
      if (err_fp)
        dup2(fileno(err_fp), STDERR_FILENO);
    }

    if (config->max_memory_mb > 0) {
      struct rlimit rl;
      rl.rlim_cur = (rlim_t)config->max_memory_mb * 1024 * 1024;
      rl.rlim_max = rl.rlim_cur;
      setrlimit(RLIMIT_AS, &rl);
    }
    if (config->max_cpu_percent > 0) {
      fprintf(stderr, "[libmountsandbox] Warning: CPU rate limiting not "
                      "natively supported on macOS without Docker.\n");
    }

    if (config->drop_privileges) {
      if (config->target_gid != 0) {
        if (setgid(config->target_gid) != 0) {
          perror("[libmountsandbox] setgid failed");
          exit(127);
        }
      } else {
        /* macOS nobody gid is usually -2 */
        setgid((gid_t)-2);
      }
      if (config->target_uid != 0) {
        if (setuid(config->target_uid) != 0) {
          perror("[libmountsandbox] setuid failed");
          exit(127);
        }
      } else {
        /* macOS nobody uid is usually -2 */
        setuid((uid_t)-2);
      }
    }

    execvp("sandbox-exec", exec_argv);
    perror("[libmountsandbox] execvp sandbox-exec failed");
    exit(127);
  } else {
    /* Parent process */
    int wstatus;
    unsigned int max_polls =
        config->timeout_secs > 0 ? config->timeout_secs * 10 : 0;
    unsigned int polls = 0;
    int wp = 0;

    if (config->use_pty && master_fd >= 0) {
      int flags = fcntl(master_fd, F_GETFL, 0);
      fcntl(master_fd, F_SETFL, flags | O_NONBLOCK);
    }

    while (1) {
      fd_set fds;
      int max_fd = 0;
      struct timeval tv;
      wp = waitpid(pid, &wstatus, WNOHANG);
      if (wp != 0) {
        if (config->use_pty && master_fd >= 0) {
          char buf[1024];
          int n;
          while ((n = read(master_fd, buf, sizeof(buf))) > 0) {
            if (out_fp)
              fwrite(buf, 1, n, out_fp);
          }
        }
        if (wp > 0 && WIFEXITED(wstatus)) {
          status = WEXITSTATUS(wstatus);
        } else {
          status = -1;
        }
        break;
      }

      FD_ZERO(&fds);
      if (config->use_pty && master_fd >= 0) {
        FD_SET(master_fd, &fds);
        max_fd = master_fd + 1;
      }

      tv.tv_sec = 0;
      tv.tv_usec = 100000;
      select(max_fd, &fds, NULL, NULL, &tv);

      if (config->use_pty && master_fd >= 0 && FD_ISSET(master_fd, &fds)) {
        char buf[1024];
        int n;
        while ((n = read(master_fd, buf, sizeof(buf))) > 0) {
          if (out_fp)
            fwrite(buf, 1, n, out_fp);
        }
      }

      if (config->timeout_secs > 0) {
        polls++;
        if (polls >= max_polls) {
          kill(pid, SIGKILL);
          waitpid(pid, &wstatus, 0);
          status = 124;
          break;
        }
      }
    }

    if (config->use_pty && master_fd >= 0) {
      close(master_fd);
    }
  }

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

  free(exec_argv);
  free(profile);
  return status;
}

#elif defined(__linux__)
/* ========================================================================= */
/* Linux Namespaces (Bubblewrap) Implementation                              */
/* ========================================================================= */

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/**
 * \brief Initializes the engine.
 * \return 0 on success, or -1 on error.
 */
static int native_init(void) {
  /* In a full implementation, this could verify 'bwrap' is in PATH */
  return 0;
}

/**
 * \brief Executes a command in the sandbox synchronously.
 * \param config Sandbox configuration.
 * \param argc Argument count.
 * \param argv Argument vector.
 * \return Exit status, or -1 on error.
 */
static int native_execute(const sandbox_config_t *config, int argc,
                          char **argv) {
  char **exec_argv;
  int i, status = -1;
  pid_t pid;
  int master_fd = -1;
  int current_arg = 0;
  int base_args = 10; /* bwrap --ro-bind / / --dev-bind /dev /dev */
  char **vstr_array = NULL;
  FILE *out_fp = NULL;
  FILE *err_fp = NULL;

  if (!config || !argv)
    return -1;

#if defined(_MSC_VER)
  if (config->stdout_buffer)
    tmpfile_s(&out_fp);
#else
  if (config->stdout_buffer)
    out_fp = tmpfile();
#endif
#if defined(_MSC_VER)
  if (config->stderr_buffer)
    tmpfile_s(&err_fp);
#else
  if (config->stderr_buffer)
    err_fp = tmpfile();
#endif

  if (config->disable_network) {
    base_args += 1; /* --unshare-net */
  }
  if (config->seccomp_profile_path) {
    base_args += 2; /* --seccomp FD */
  }

  if (config->denied_syscalls && config->denied_syscall_count > 0) {
    base_args +=
        (int)(config->denied_syscall_count * 2); /* --cap-drop SYSCALL */
  }

  if (config->mounts && config->mount_count > 0) {
    base_args +=
        (int)(config->mount_count * 3); /* --bind / --ro-bind, SRC, DEST */
  }

  exec_argv = (char **)malloc((size_t)(argc + base_args + 1) * sizeof(char *));
  if (!exec_argv) {
    return -1;
  }

  exec_argv[current_arg++] = (char *)"bwrap";
  exec_argv[current_arg++] = (char *)"--ro-bind";
  exec_argv[current_arg++] = (char *)"/";
  exec_argv[current_arg++] = (char *)"/";
  exec_argv[current_arg++] = (char *)"--dev-bind";
  exec_argv[current_arg++] = (char *)"/dev";
  exec_argv[current_arg++] = (char *)"/dev";

  if (config->disable_network) {
    exec_argv[current_arg++] = (char *)"--unshare-net";
  }
  if (config->seccomp_profile_path) {
    exec_argv[current_arg++] = (char *)"--seccomp";
    /* We will open the fd and set the string later before execvp */
    exec_argv[current_arg++] = (char *)"_SECCOMP_FD_";
  }

  if (config->denied_syscalls && config->denied_syscall_count > 0) {
    size_t c;
    fprintf(stderr, "[libmountsandbox] Warning: Translating Linux seccomp deny "
                    "into capabilities drop for bwrap.\n");
    for (c = 0; c < config->denied_syscall_count; c++) {
      exec_argv[current_arg++] = (char *)"--cap-drop";
      exec_argv[current_arg++] = (char *)config->denied_syscalls[c];
    }
  }

  if (config->mounts && config->mount_count > 0) {
    vstr_array = (char **)malloc((size_t)(config->mount_count * PATH_MAX));
    if (!vstr_array) {
      free(exec_argv);
      return -1;
    }

    {
      size_t m;
      for (m = 0; m < config->mount_count; m++) {
        vstr_array[m] = (char *)malloc((size_t)PATH_MAX);
        if (realpath(config->mounts[m].dir, vstr_array[m]) == NULL) {
          perror("[libmountsandbox] realpath failed");
#if defined(_MSC_VER)
          strcpy_s(vstr_array[m], PATH_MAX, config->mounts[m].dir);
#else
          strcpy(vstr_array[m], config->mounts[m].dir); /* Fallback */
#endif
        }

        if (config->mounts[m].read_only) {
          exec_argv[current_arg++] = (char *)"--ro-bind";
        } else {
          exec_argv[current_arg++] = (char *)"--bind";
        }
        exec_argv[current_arg++] = vstr_array[m];
        exec_argv[current_arg++] = vstr_array[m];
      }
    }
  }

  for (i = 0; i < argc; i++) {
    exec_argv[current_arg++] = argv[i];
  }
  exec_argv[current_arg] = NULL;

  pid = fork();
  if (pid < 0) {
    status = -1;
  } else if (pid == 0) {
    /* Child process */
    if (config->env_vars && config->env_count > 0) {
      size_t e;
      for (e = 0; e < config->env_count; e++) {
        putenv((char *)config->env_vars[e]);
      }
    }
    if (config->use_pty && master_fd >= 0) {
      char *slave_name = ptsname(master_fd);
      int slave_fd = open(slave_name, O_RDWR);
      setsid();
      dup2(slave_fd, STDIN_FILENO);
      dup2(slave_fd, STDOUT_FILENO);
      dup2(slave_fd, STDERR_FILENO);
      close(slave_fd);
      close(master_fd);
    } else {
      if (out_fp)
        dup2(fileno(out_fp), STDOUT_FILENO);
      if (err_fp)
        dup2(fileno(err_fp), STDERR_FILENO);
    }

    if (config->max_memory_mb > 0) {
      struct rlimit rl;
      rl.rlim_cur = (rlim_t)config->max_memory_mb * 1024 * 1024;
      rl.rlim_max = rl.rlim_cur;
      setrlimit(RLIMIT_AS, &rl);
    }
    if (config->max_cpu_percent > 0) {
      fprintf(stderr, "[libmountsandbox] Warning: CPU rate limiting not "
                      "natively supported via bwrap without Cgroups/Docker.\n");
    }

    execvp("bwrap", exec_argv);
    perror("[libmountsandbox] execvp bwrap failed");
    exit(127);
  } else {
    /* Parent process */
    int wstatus;
    unsigned int max_polls =
        config->timeout_secs > 0 ? config->timeout_secs * 10 : 0;
    unsigned int polls = 0;
    int wp = 0;

    if (config->use_pty && master_fd >= 0) {
      int flags = fcntl(master_fd, F_GETFL, 0);
      fcntl(master_fd, F_SETFL, flags | O_NONBLOCK);
    }

    while (1) {
      fd_set fds;
      int max_fd = 0;
      struct timeval tv;
      wp = waitpid(pid, &wstatus, WNOHANG);
      if (wp != 0) {
        if (config->use_pty && master_fd >= 0) {
          char buf[1024];
          int n;
          while ((n = read(master_fd, buf, sizeof(buf))) > 0) {
            if (out_fp)
              fwrite(buf, 1, n, out_fp);
          }
        }
        if (wp > 0 && WIFEXITED(wstatus)) {
          status = WEXITSTATUS(wstatus);
        } else {
          status = -1;
        }
        break;
      }

      FD_ZERO(&fds);
      if (config->use_pty && master_fd >= 0) {
        FD_SET(master_fd, &fds);
        max_fd = master_fd + 1;
      }

      tv.tv_sec = 0;
      tv.tv_usec = 100000;
      select(max_fd, &fds, NULL, NULL, &tv);

      if (config->use_pty && master_fd >= 0 && FD_ISSET(master_fd, &fds)) {
        char buf[1024];
        int n;
        while ((n = read(master_fd, buf, sizeof(buf))) > 0) {
          if (out_fp)
            fwrite(buf, 1, n, out_fp);
        }
      }

      if (config->timeout_secs > 0) {
        polls++;
        if (polls >= max_polls) {
          kill(pid, SIGKILL);
          waitpid(pid, &wstatus, 0);
          status = 124;
          break;
        }
      }
    }

    if (config->use_pty && master_fd >= 0) {
      close(master_fd);
    }
  }

  if (vstr_array) {
    size_t m;
    for (m = 0; m < config->mount_count; m++) {
      free(vstr_array[m]);
    }
    free(vstr_array);
  }

  if (config->drop_privileges) {
    /* Find and free dynamically allocated uid and gid strings */
    int j;
    for (j = 0; j < current_arg; j++) {
      if (exec_argv[j] && j > 0) {
        if (strcmp(exec_argv[j - 1], "--uid") == 0 ||
            strcmp(exec_argv[j - 1], "--gid") == 0) {
          free(exec_argv[j]);
        }
      }
    }
  }

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

  free(exec_argv);
  return status;
}

#elif defined(_WIN32)
/* ========================================================================= */
/* Windows Job Objects Implementation                                        */
/* ========================================================================= */

/**
 * \brief Initializes the engine.
 * \return 0 on success, or -1 on error.
 */
static int native_init(void) { return 0; }

/**
 * \brief Executes a command in the sandbox synchronously.
 * \param config Sandbox configuration.
 * \param argc Argument count.
 * \param argv Argument vector.
 * \return Exit status, or -1 on error.
 */
static int native_execute(const sandbox_config_t *config, int argc,
                          char **argv) {
  HANDLE hJob;
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli;
  STARTUPINFO si;
  PROCESS_INFORMATION pi;
  int i, status = -1;
  size_t cmdline_len = 0;
  char *cmdline;
  DWORD exit_code;
  FILE *out_fp = NULL;
  FILE *err_fp = NULL;

  const char *start_dir = NULL;

  if (!config || !argv)
    return -1;

#if defined(_MSC_VER)
  if (config->stdout_buffer)
    tmpfile_s(&out_fp);
#else
  if (config->stdout_buffer)
    out_fp = tmpfile();
#endif
#if defined(_MSC_VER)
  if (config->stderr_buffer)
    tmpfile_s(&err_fp);
#else
  if (config->stderr_buffer)
    err_fp = tmpfile();
#endif

  if (config->mounts && config->mount_count > 0) {
    start_dir = config->mounts[0].dir;
  }

  /* Build command line string */
  for (i = 0; i < argc; i++) {
    cmdline_len += strlen(argv[i]) + 3; /* quotes + space */
  }

  cmdline = (char *)malloc(cmdline_len + 1);
  if (!cmdline)
    return -1;
  cmdline[0] = '\0';

  for (i = 0; i < argc; i++) {
#if defined(_MSC_VER)
    strcat_s(cmdline, cmdline_len + 1, "\"");
#else
    strcat(cmdline, "\"");
#endif
#if defined(_MSC_VER)
    strcat_s(cmdline, cmdline_len + 1, argv[i]);
#else
    strcat(cmdline, argv[i]);
#endif
#if defined(_MSC_VER)
    strcat_s(cmdline, cmdline_len + 1, "\" ");
#else
    strcat(cmdline, "\" ");
#endif
  }

  /* Create a Job Object to restrict the process */
  hJob = CreateJobObject(NULL, NULL);
  if (hJob == NULL) {
    fprintf(stderr, "[libmountsandbox] CreateJobObject failed (%lu)\n",
            GetLastError());
    free(cmdline);
    return -1;
  }

  /* Set basic restrictions */
  memset(&jeli, 0, sizeof(jeli));
  jeli.BasicLimitInformation.LimitFlags =
      JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION |
      JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
  jeli.BasicLimitInformation.ActiveProcessLimit = 10; /* Prevent fork bombs */

  if (config->max_memory_mb > 0) {
    jeli.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
    jeli.ProcessMemoryLimit = (SIZE_T)config->max_memory_mb * 1024 * 1024;
  }

  if (config->max_cpu_percent > 0) {
    fprintf(stderr, "[libmountsandbox] Warning: CPU rate limiting not enabled "
                    "on baseline Windows Job Objects without newer flags.\n");
  }

  if (config->denied_syscalls && config->denied_syscall_count > 0) {
    fprintf(
        stderr,
        "[libmountsandbox] Warning: Fine-grained Syscall filtering (Seccomp) "
        "is not natively supported via Windows Job Objects. Ignored.\n");
  }

  if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli,
                               sizeof(jeli))) {
    fprintf(stderr, "[libmountsandbox] SetInformationJobObject failed (%lu)\n",
            GetLastError());
    CloseHandle(hJob);
    free(cmdline);
    return -1;
  }

  if (config->disable_network) {
    /* Note: Network disabling natively on Windows requires Windows Filtering
     * Platform (WFP), AppContainers, or Firewall rules, which is highly complex
     * in raw C89. For this baseline, we warn the user. */
    fprintf(stderr, "[libmountsandbox] Warning: Network disabling not natively "
                    "supported in Windows Job Objects yet.\n");
  }

  if (config->env_vars && config->env_count > 0) {
    size_t e;
    for (e = 0; e < config->env_count; e++) {
      _putenv((char *)config->env_vars[e]);
    }
  }

  memset(&si, 0, sizeof(si));
  si.cb = sizeof(si);
  if (out_fp || err_fp) {
    si.dwFlags |= STARTF_USESTDHANDLES;
    if (out_fp)
      si.hStdOutput = (HANDLE)_get_osfhandle(_fileno(out_fp));
    else
      si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);

    if (err_fp)
      si.hStdError = (HANDLE)_get_osfhandle(_fileno(err_fp));
    else
      si.hStdError = GetStdHandle(STD_ERROR_HANDLE);

    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  }
  memset(&pi, 0, sizeof(pi));

  /* Start process suspended so we can assign it to the job before it runs */
  if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE,
                      CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB, NULL,
                      start_dir, &si, &pi)) {
    fprintf(stderr, "[libmountsandbox] CreateProcess failed (%lu)\n",
            GetLastError());
    CloseHandle(hJob);
    free(cmdline);
    return -1;
  }

  /* Assign process to the restricted job */
  if (!AssignProcessToJobObject(hJob, pi.hProcess)) {
    fprintf(stderr, "[libmountsandbox] AssignProcessToJobObject failed (%lu)\n",
            GetLastError());
    TerminateProcess(pi.hProcess, 1);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hJob);
    free(cmdline);
    return -1;
  }

  /* Resume execution */
  ResumeThread(pi.hThread);

  /* Wait for process to exit */
  if (config->timeout_secs > 0) {
    if (WaitForSingleObject(pi.hProcess, config->timeout_secs * 1000) ==
        WAIT_TIMEOUT) {
      TerminateProcess(pi.hProcess, 1);
      status = 124;
    } else {
      if (GetExitCodeProcess(pi.hProcess, &exit_code)) {
        status = (int)exit_code;
      }
    }
  } else {
    WaitForSingleObject(pi.hProcess, INFINITE);
    if (GetExitCodeProcess(pi.hProcess, &exit_code)) {
      status = (int)exit_code;
    }
  }

  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(hJob);
  free(cmdline);

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

  return status;
}

#else
/* ========================================================================= */
/* Unsupported Platform Stub                                                 */
/* ========================================================================= */
static int native_init(void) { return -1; }

/**
 * \brief Executes a command in the sandbox synchronously.
 * \param config Sandbox configuration.
 * \param argc Argument count.
 * \param argv Argument vector.
 * \return Exit status, or -1 on error.
 */
static int native_execute(const sandbox_config_t *config, int argc,
                          char **argv) {
  (void)config;
  (void)argc;
  (void)argv;
  fprintf(stderr,
          "[libmountsandbox] Native sandbox not supported on this platform.\n");
  return -1;
}

#endif

/**
 * \brief Executes a command in the sandbox asynchronously.
 * \param config Sandbox configuration.
 * \param argc Argument count.
 * \param argv Argument vector.
 * \param out_process Pointer to receive the process handle.
 * \return 0 on success, or -1 on error.
 */
static int native_execute_async(const sandbox_config_t *config, int argc,
                                char **argv, sandbox_process_t **out_process) {
  (void)config;
  (void)argc;
  (void)argv;
  fprintf(stderr, "[libmountsandbox] Async execution is a work in progress for "
                  "native. Falling back to sync.\n");
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
static int native_wait_process(sandbox_process_t *process, int *exit_status) {
  (void)process;
  (void)exit_status;
  return -1;
}

/**
 * \brief Frees an asynchronous process handle.
 * \param process The process handle.
 */
static void native_free_process(sandbox_process_t *process) { (void)process; }

/**
 * \brief Cleans up the engine resources.
 */
static void native_cleanup(void) { /* No persistent resources to clean up */ }

/**
 * \brief The Native OS sandbox engine export.
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
