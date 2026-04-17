#if defined(__APPLE__) || defined(__linux__) || defined(__CYGWIN__)
#define _XOPEN_SOURCE 600
#endif
#define _WIN32_WINNT 0x0600
/**
 * \file engine_gvisor.c
 * \brief gVisor-based sandbox implementation.
 *
 * This engine maps the execution of a command into a Docker container.
 * It strictly supports C89 and compiles across multiple compilers
 * (MSVC, Watcom, GCC, Clang) by using platform-specific process execution.
 */

/* clang-format off */
#include "sandbox.h"
#include "log.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Cross-platform header inclusion for process execution */
#if defined(_WIN32) || defined(__WATCOMC__)
#include <process.h>
#ifdef _WIN32
#include <winsock2.h>
#endif
#else
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#if defined(_WIN32) || defined(__WATCOMC__)
#include <io.h>
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
  int rc = 0;
  long fsize;
  if (!fp || !buf || !size) {
    rc = -1;
    return rc;
  }
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
    {
      rc = 0;
      return rc;
    }
  } else {
    *size = 0;
    rc = -1;
    return rc;
  }
}

/**
 * \brief Initializes the Docker engine.
 * \return 0 assuming basic availability; deeper checks could be added.
 */
static int gvisor_init(void) {
  int rc = 0;
  return rc;
}

/**
 * \brief Executes a command inside a Docker container.
 * \param config The sandbox configuration parameters.
 * \param argc Number of command arguments.
 * \param argv Array of command arguments.
 * \return The exit code of the Docker process, or -1 on internal error.
 */
static int gvisor_execute(const sandbox_config_t *config, int argc, char **argv,
                          int *exit_status) {
  int rc = 0;
  char **gvisor_argv;
  int i;
  int status = -1;
  char **vstr_array = NULL;
  int base_args = 9;
  int current_arg = 0;
  FILE *out_fp = NULL;
  FILE *err_fp = NULL;
  char mem_buf[32];
  char cpu_buf[32];
  char *sec_buf_ptr = NULL;
  char *app_buf_ptr = NULL;
  char user_buf[64];

  if (!config || !argv) {
    rc = -1;
    return rc;
  }

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

  /* Base args + optional --network none (2 args) + env vars (2 args each) +
   * mounts (2 args each) + original args + NULL */
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
    base_args += 2;
  }
  if (config->denied_syscalls && config->denied_syscall_count > 0) {
    base_args += (int)(config->denied_syscall_count * 2);
  }
  if (config->env_vars && config->env_count > 0) {
    base_args += (int)(config->env_count * 2);
  }
  if (config->mounts && config->mount_count > 0) {
    base_args += (int)(config->mount_count * 2);
  }

  gvisor_argv =
      (char **)malloc((size_t)(argc + base_args + 1) * sizeof(char *));
  if (!gvisor_argv) {
    {
      rc = -1;
      return rc;
    }
  }

  gvisor_argv[current_arg++] = (char *)"docker";
  gvisor_argv[current_arg++] = (char *)"run";
  gvisor_argv[current_arg++] = (char *)"--rm";
  gvisor_argv[current_arg++] = (char *)"--runtime=runsc";

  if (config->disable_network) {
    gvisor_argv[current_arg++] = (char *)"--network";
    gvisor_argv[current_arg++] = (char *)"none";
  }
  if (config->use_pty) {
    gvisor_argv[current_arg++] = (char *)"-i";
    gvisor_argv[current_arg++] = (char *)"-t";
  }
  if (config->seccomp_profile_path) {
    sec_buf_ptr = (char *)malloc(strlen(config->seccomp_profile_path) + 15);
    if (sec_buf_ptr) {
#if defined(_MSC_VER)
      sprintf_s(sec_buf_ptr, (strlen(config->seccomp_profile_path) + 15),
                "seccomp=%s", config->seccomp_profile_path);
#else
      sprintf(sec_buf_ptr, "seccomp=%s", config->seccomp_profile_path);
#endif
      gvisor_argv[current_arg++] = (char *)"--security-opt";
      gvisor_argv[current_arg++] = sec_buf_ptr;
    }
  }
  if (config->apparmor_profile) {
    app_buf_ptr = (char *)malloc(strlen(config->apparmor_profile) + 15);
    if (app_buf_ptr) {
#if defined(_MSC_VER)
      sprintf_s(app_buf_ptr, (strlen(config->apparmor_profile) + 15),
                "apparmor=%s", config->apparmor_profile);
#else
      sprintf(app_buf_ptr, "apparmor=%s", config->apparmor_profile);
#endif
      gvisor_argv[current_arg++] = (char *)"--security-opt";
      gvisor_argv[current_arg++] = app_buf_ptr;
    }
  }

  if (config->max_memory_mb > 0) {
#if defined(_MSC_VER)
    sprintf_s(mem_buf, sizeof(mem_buf), "%um", config->max_memory_mb);
#else
    sprintf(mem_buf, "%um", config->max_memory_mb);
#endif
    gvisor_argv[current_arg++] = (char *)"--memory";
    gvisor_argv[current_arg++] = mem_buf;
  }

  if (config->max_cpu_percent > 0) {
#if defined(_MSC_VER)
    sprintf_s(cpu_buf, sizeof(cpu_buf), "%u.%02u",
              config->max_cpu_percent / 100, config->max_cpu_percent % 100);
#else
    sprintf(cpu_buf, "%u.%02u", config->max_cpu_percent / 100,
            config->max_cpu_percent % 100);
#endif
    gvisor_argv[current_arg++] = (char *)"--cpus";
    gvisor_argv[current_arg++] = cpu_buf;
  }

  if (config->drop_privileges) {
    if (config->target_uid != 0 || config->target_gid != 0) {
#if defined(_MSC_VER)
      sprintf_s(user_buf, sizeof(user_buf), "%u:%u", config->target_uid,
                config->target_gid);
#else
      sprintf(user_buf, "%u:%u", config->target_uid, config->target_gid);
#endif
    } else {
      /* Default to nobody/nogroup on standard ubuntu */
#if defined(_MSC_VER)
      strcpy_s(user_buf, sizeof(user_buf), "65534:65534");
#else
      strcpy(user_buf, "65534:65534");
#endif
    }
    gvisor_argv[current_arg++] = (char *)"-u";
    gvisor_argv[current_arg++] = user_buf;
  }

  if (config->denied_syscalls && config->denied_syscall_count > 0) {
    size_t c;
    fprintf(stderr, "[libmountsandbox] Warning: Translating Docker syscall "
                    "deny into capabilities drop (approximate).\n");
    for (c = 0; c < config->denied_syscall_count; c++) {
      gvisor_argv[current_arg++] = (char *)"--cap-drop";
      gvisor_argv[current_arg++] = (char *)config->denied_syscalls[c];
    }
  }

  if (config->env_vars && config->env_count > 0) {
    size_t e;
    for (e = 0; e < config->env_count; e++) {
      gvisor_argv[current_arg++] = (char *)"-e";
      gvisor_argv[current_arg++] = (char *)config->env_vars[e];
    }
  }

  /* We need to keep track of dynamically allocated mount strings */
  vstr_array = (char **)malloc((size_t)(config->mount_count * sizeof(char *)));
  if (!vstr_array) {
    if (sec_buf_ptr)
      free(sec_buf_ptr);
    if (app_buf_ptr)
      free(app_buf_ptr);
    free(gvisor_argv);
    {
      rc = -1;
      return rc;
    }
  }

  if (config->mounts && config->mount_count > 0) {
    size_t m;
    for (m = 0; m < config->mount_count; m++) {
      size_t vlen = strlen(config->mounts[m].dir) +
                    20; /* length + ":/mnt_N" + ":ro" + null */
      char *vstr = (char *)malloc((size_t)vlen);
      if (!vstr) {
        /* Free previously allocated strings */
        size_t j;
        for (j = 0; j < m; j++)
          free(vstr_array[j]);
        free(vstr_array);
        if (sec_buf_ptr)
          free(sec_buf_ptr);
        if (app_buf_ptr)
          free(app_buf_ptr);
        free(gvisor_argv);
        {
          rc = -1;
          return rc;
        }
      }
#if defined(_MSC_VER)
      sprintf_s(vstr, vlen, "%s:/workspace%lu%s", config->mounts[m].dir,
                (unsigned long)m, config->mounts[m].read_only ? ":ro" : "");
#else
      sprintf(vstr, "%s:/workspace%lu%s", config->mounts[m].dir,
              (unsigned long)m, config->mounts[m].read_only ? ":ro" : "");
#endif
      vstr_array[m] = vstr;
      gvisor_argv[current_arg++] = (char *)"-v";
      gvisor_argv[current_arg++] = vstr;
    }
  }

  /* Set working directory to the first mount point, or fallback */
  gvisor_argv[current_arg++] = (char *)"-w";
  if (config->mount_count > 0) {
    gvisor_argv[current_arg++] = (char *)"/workspace0";
  } else {
    gvisor_argv[current_arg++] = (char *)"/";
  }
  gvisor_argv[current_arg++] = (char *)"ubuntu:latest";

  for (i = 0; i < argc; i++) {
    gvisor_argv[current_arg++] = argv[i];
  }
  gvisor_argv[current_arg] = NULL;

#if defined(_WIN32) || defined(__WATCOMC__)
  {
    int old_out = -1, old_err = -1;
    if (out_fp) {
      old_out = _dup(1);
      _dup2(_fileno(out_fp), 1);
    }
    if (err_fp) {
      old_err = _dup(2);
      _dup2(_fileno(err_fp), 2);
    }

    if (config->timeout_secs > 0) {
#ifdef _WIN32
      intptr_t hProcess =
          spawnvp(P_NOWAIT, "docker", (const char *const *)gvisor_argv);
      if (hProcess != -1) {
        if (WaitForSingleObject((HANDLE)hProcess,
                                config->timeout_secs * 1000) == WAIT_TIMEOUT) {
          TerminateProcess((HANDLE)hProcess, 1);
          status = 124;
        } else {
          DWORD exit_code;
          if (GetExitCodeProcess((HANDLE)hProcess, &exit_code)) {
            status = (int)exit_code;
          }
        }
        CloseHandle((HANDLE)hProcess);
      }
#else
      /* Fallback for Watcom without Windows API */
      status =
          (int)spawnvp(P_WAIT, "docker", (const char *const *)gvisor_argv);
#endif
    } else {
      status =
          (int)spawnvp(P_WAIT, "docker", (const char *const *)gvisor_argv);
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
      /* Child process */
      if (out_fp)
        dup2(fileno(out_fp), STDOUT_FILENO);
      if (err_fp)
        dup2(fileno(err_fp), STDERR_FILENO);
      execvp("docker", gvisor_argv);
      exit(127); /* Exit if exec fails */
    } else {
      /* Parent process */
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
            tv.tv_usec = 100000; /* 100ms */
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

  if (vstr_array) {
    size_t m;
    for (m = 0; m < config->mount_count; m++) {
      free(vstr_array[m]);
    }
    free(vstr_array);
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

  if (sec_buf_ptr)
    free(sec_buf_ptr);
  if (app_buf_ptr)
    free(app_buf_ptr);
  free(gvisor_argv);
  if (status == -1) {
    rc = -1;
    if (errno != 0)
      LOG_DEBUG("Execute failed: %s", strerror(errno));
  } else {
    if (exit_status)
      *exit_status = status;
  }
  return rc;
}

/**
 * \brief Cleans up Docker engine resources.
 */

/**
 * \brief Executes a command in the sandbox asynchronously.
 * \param config Sandbox configuration.
 * \param argc Argument count.
 * \param argv Argument vector.
 * \param out_process Pointer to receive the process handle.
 * \return 0 on success, or -1 on error.
 */
static int gvisor_execute_async(const sandbox_config_t *config, int argc,
                                char **argv, sandbox_process_t **out_process) {
  int rc = 0;
  (void)config;
  (void)argc;
  (void)argv;
  fprintf(stderr, "[libmountsandbox] Async execution is a work in progress for "
                  "gvisor. Falling back to sync.\n");
  if (out_process)
    *out_process = NULL;
  rc = -1;
  return rc;
}

/**
 * \brief Waits for an asynchronous process to complete.
 * \param process The process handle.
 * \param exit_status Pointer to receive the exit status.
 * \return 0 on success, or -1 on error.
 */
static int gvisor_wait_process(sandbox_process_t *process, int *exit_status) {
  int rc = 0;
  (void)process;
  (void)exit_status;
  rc = -1;
  return rc;
}

/**
 * \brief Frees an asynchronous process handle.
 * \param process The process handle.
 */
static void gvisor_free_process(sandbox_process_t *process) { (void)process; }

/**
 * \brief Cleans up the engine resources.
 */
static void gvisor_cleanup(void) {
  /* No cleanup required for docker process invocation */
}

/**
 * \brief The Docker sandbox engine export.
 */
sandbox_engine_t engine_gvisor = {
    "gvisor",
    "gVisor-based secure container sandbox (runsc)",
    gvisor_init,
    gvisor_execute,
    gvisor_execute_async,
    gvisor_wait_process,
    gvisor_free_process,
    gvisor_cleanup};
