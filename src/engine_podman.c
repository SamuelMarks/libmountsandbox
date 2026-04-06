/**
 * \file engine_podman.c
 * \brief Podman-based sandbox implementation.
 *
 * This engine maps the execution of a command into a Podman container.
 * It strictly supports C89 and compiles across multiple compilers 
 * (MSVC, Watcom, GCC, Clang) by using platform-specific process execution.
 */

#include "sandbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Cross-platform header inclusion for process execution */
#if defined(_WIN32) || defined(__WATCOMC__)
#include <process.h>
#ifdef _WIN32
#include <windows.h>
#endif
#else
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <signal.h>
#endif

#if defined(_WIN32) || defined(__WATCOMC__)
#include <io.h>
#endif

static int read_fp_to_buffer(FILE *fp, char **buf, size_t *size) {
    long fsize;
    if (!fp || !buf || !size) return -1;
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    rewind(fp);
    if (fsize < 0) fsize = 0;
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
 * \brief Initializes the Podman engine.
 * \return 0 assuming basic availability; deeper checks could be added.
 */
static int podman_init(void) {
    return 0;
}

/**
 * \brief Executes a command inside a Podman container.
 * \param config The sandbox configuration parameters.
 * \param argc Number of command arguments.
 * \param argv Array of command arguments.
 * \return The exit code of the Podman process, or -1 on internal error.
 */
static int podman_execute(const sandbox_config_t *config, int argc, char **argv) {
    char **podman_argv;
    int i;
    int status = -1;
    char **vstr_array = NULL;
    int base_args = 8;
    int current_arg = 0;
    FILE *out_fp = NULL;
    FILE *err_fp = NULL;
    char mem_buf[32];
    char cpu_buf[32];
    char *sec_buf_ptr = NULL;
    char *app_buf_ptr = NULL;
    char user_buf[64];

    if (!config || !argv) return -1;

    if (config->stdout_buffer) out_fp = tmpfile();
    if (config->max_network_mbps > 0) {
        fprintf(stderr, "[libmountsandbox] Warning: Network bandwidth throttling (max_network_mbps) is not natively enforced by this engine.\n");
    }
    if (config->stderr_buffer) err_fp = tmpfile();

    /* Base args + optional --network none (2 args) + env vars (2 args each) + mounts (2 args each) + original args + NULL */
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
    if (config->env_vars && config->env_count > 0) {
        base_args += (int)(config->env_count * 2);
    }
    if (config->mounts && config->mount_count > 0) {
        base_args += (int)(config->mount_count * 2);
    }

    podman_argv = (char**)malloc((size_t)(argc + base_args + 1) * sizeof(char*));
    if (!podman_argv) {
        return -1;
    }

    podman_argv[current_arg++] = (char*)"podman";
    podman_argv[current_arg++] = (char*)"run";
    podman_argv[current_arg++] = (char*)"--rm";
    
    if (config->disable_network) {
        podman_argv[current_arg++] = (char*)"--network";
        podman_argv[current_arg++] = (char*)"none";
    }
    if (config->use_pty) {
        podman_argv[current_arg++] = (char*)"-i";
        podman_argv[current_arg++] = (char*)"-t";
    }
    if (config->seccomp_profile_path) {
        sec_buf_ptr = (char*)malloc(strlen(config->seccomp_profile_path) + 15);
        if (sec_buf_ptr) {
            sprintf(sec_buf_ptr, "seccomp=%s", config->seccomp_profile_path);
            podman_argv[current_arg++] = (char*)"--security-opt";
            podman_argv[current_arg++] = sec_buf_ptr;
        }
    }
    if (config->apparmor_profile) {
        app_buf_ptr = (char*)malloc(strlen(config->apparmor_profile) + 15);
        if (app_buf_ptr) {
            sprintf(app_buf_ptr, "apparmor=%s", config->apparmor_profile);
            podman_argv[current_arg++] = (char*)"--security-opt";
            podman_argv[current_arg++] = app_buf_ptr;
        }
    }

    if (config->max_memory_mb > 0) {
        snprintf(mem_buf, sizeof(mem_buf), "%um", config->max_memory_mb);
        podman_argv[current_arg++] = (char*)"--memory";
        podman_argv[current_arg++] = mem_buf;
    }

    if (config->max_cpu_percent > 0) {
        snprintf(cpu_buf, sizeof(cpu_buf), "%u.%02u", config->max_cpu_percent / 100, config->max_cpu_percent % 100);
        podman_argv[current_arg++] = (char*)"--cpus";
        podman_argv[current_arg++] = cpu_buf;
    }

    if (config->drop_privileges) {
        if (config->target_uid != 0 || config->target_gid != 0) {
            snprintf(user_buf, sizeof(user_buf), "%u:%u", config->target_uid, config->target_gid);
        } else {
            /* Default to nobody/nogroup on standard ubuntu */
            strcpy(user_buf, "65534:65534");
        }
        podman_argv[current_arg++] = (char*)"-u";
        podman_argv[current_arg++] = user_buf;
    }

    if (config->denied_syscalls && config->denied_syscall_count > 0) {
        size_t c;
        fprintf(stderr, "[libmountsandbox] Warning: Translating Podman syscall deny into capabilities drop (approximate).\n");
        for (c = 0; c < config->denied_syscall_count; c++) {
            podman_argv[current_arg++] = (char*)"--cap-drop";
            podman_argv[current_arg++] = (char*)config->denied_syscalls[c];
        }
    }

    if (config->env_vars && config->env_count > 0) {
        size_t e;
        for (e = 0; e < config->env_count; e++) {
            podman_argv[current_arg++] = (char*)"-e";
            podman_argv[current_arg++] = (char*)config->env_vars[e];
        }
    }

    /* We need to keep track of dynamically allocated mount strings */
    vstr_array = (char**)malloc((size_t)(config->mount_count * sizeof(char*)));
    if (!vstr_array) {
        if (sec_buf_ptr) free(sec_buf_ptr);
    if (app_buf_ptr) free(app_buf_ptr);
    free(podman_argv);
        return -1;
    }

    if (config->mounts && config->mount_count > 0) {
        size_t m;
        for (m = 0; m < config->mount_count; m++) {
            size_t vlen = strlen(config->mounts[m].dir) + 20; /* length + ":/mnt_N" + ":ro" + null */
            char *vstr = (char*)malloc((size_t)vlen);
            if (!vstr) {
                /* Free previously allocated strings */
                size_t j;
                for (j = 0; j < m; j++) free(vstr_array[j]);
                free(vstr_array);
                if (sec_buf_ptr) free(sec_buf_ptr);
    if (app_buf_ptr) free(app_buf_ptr);
    free(podman_argv);
                return -1;
            }
            snprintf(vstr, vlen, "%s:/workspace%lu%s", config->mounts[m].dir, (unsigned long)m, config->mounts[m].read_only ? ":ro" : "");
            vstr_array[m] = vstr;
            podman_argv[current_arg++] = (char*)"-v";
            podman_argv[current_arg++] = vstr;
        }
    }

    /* Set working directory to the first mount point, or fallback */
    podman_argv[current_arg++] = (char*)"-w";
    if (config->mount_count > 0) {
        podman_argv[current_arg++] = (char*)"/workspace0";
    } else {
        podman_argv[current_arg++] = (char*)"/";
    }
    podman_argv[current_arg++] = (char*)"ubuntu:latest";

    for (i = 0; i < argc; i++) {
        podman_argv[current_arg++] = argv[i];
    }
    podman_argv[current_arg] = NULL;

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
            intptr_t hProcess = _spawnvp(_P_NOWAIT, "podman", (const char* const*)podman_argv);
            if (hProcess != -1) {
                if (WaitForSingleObject((HANDLE)hProcess, config->timeout_secs * 1000) == WAIT_TIMEOUT) {
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
            status = (int)_spawnvp(_P_WAIT, "podman", (const char* const*)podman_argv);
#endif
        } else {
            status = (int)_spawnvp(_P_WAIT, "podman", (const char* const*)podman_argv);
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
            if (out_fp) dup2(fileno(out_fp), STDOUT_FILENO);
            if (err_fp) dup2(fileno(err_fp), STDERR_FILENO);
            execvp("podman", podman_argv);
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
                    if (wp != 0) break;
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
    
    if (out_fp && config->stdout_buffer) { if (read_fp_to_buffer(out_fp, config->stdout_buffer, config->stdout_size) != 0) { status = -1; } fclose(out_fp); }
    if (err_fp && config->stderr_buffer) { if (read_fp_to_buffer(err_fp, config->stderr_buffer, config->stderr_size) != 0) { status = -1; } fclose(err_fp); }
    
    if (sec_buf_ptr) free(sec_buf_ptr);
    if (app_buf_ptr) free(app_buf_ptr);
    free(podman_argv);
    return status;
}

/**
 * \brief Cleans up Podman engine resources.
 */

static sandbox_process_t* podman_execute_async(const sandbox_config_t *config, int argc, char **argv) {
    (void)config; (void)argc; (void)argv;
    fprintf(stderr, "[libmountsandbox] Async execution is a work in progress for podman. Falling back to sync.\n");
    return NULL;
}

static int podman_wait_process(sandbox_process_t *process, int *exit_status) {
    (void)process; (void)exit_status;
    return -1;
}

static void podman_free_process(sandbox_process_t *process) {
    (void)process;
}

static void podman_cleanup(void) {
    /* No cleanup required for podman process invocation */
}

/**
 * \brief The Podman sandbox engine export.
 */
sandbox_engine_t engine_podman = {
    "podman",
    "Podman-based secure container sandbox",
    podman_init,
    podman_execute,
    podman_execute_async,
    podman_wait_process,
    podman_free_process,
    podman_cleanup
};
