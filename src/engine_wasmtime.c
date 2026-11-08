/**
 * @file engine_wasmtime.c
 * @brief Wasmtime-based WebAssembly sandbox implementation.
 *
 * This engine maps the execution of a WebAssembly binary into a Wasmtime
 * runtime using WASI capabilities.
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
 * @brief Initializes the Wasmtime engine.
 * @return SANDBOX_SUCCESS on initialization.
 */
static sandbox_error_t wasmtime_init(void) { return SANDBOX_SUCCESS; }

/**
 * @brief Executes a WebAssembly binary inside Wasmtime.
 * @param config The sandbox configuration parameters.
 * @param argc Number of command arguments.
 * @param argv Array of command arguments.
 * @param exit_status Pointer to receive the exit code of the Wasmtime process.
 * @return SANDBOX_SUCCESS on success, or an error enum on failure.
 */
static sandbox_error_t wasmtime_execute(const sandbox_config_t *config,
                                        int argc, char **argv,
                                        int *exit_status) {
  sandbox_error_t rc = SANDBOX_SUCCESS;
  void *raw_ptr = NULL;
  char **wasm_argv = NULL;
  int i;
  int status = -1;
  char **vstr_array = NULL;
  size_t allocated_mounts = 0;
  int base_args = 6;
  int current_arg = 0;
  FILE *out_fp = NULL;
  FILE *err_fp = NULL;
  char mem_buf[64];
  char linear_mem_buf[64];

  if (!config || argc < 1 || !argv) {
    return SANDBOX_ERR_INVALID_ARG;
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

  if (!config->disable_network) {
    base_args += 2;
  }
  if (config->max_memory_mb > 0) {
    base_args += 4;
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
  wasm_argv = (char **)raw_ptr;

  wasm_argv[current_arg++] = (char *)"wasmtime";
  wasm_argv[current_arg++] = (char *)"run";

  if (!config->disable_network) {
    wasm_argv[current_arg++] = (char *)"-S";
    wasm_argv[current_arg++] = (char *)"inherit-network=y";
  }

  if (config->max_memory_mb > 0) {
    unsigned long bytes =
        (unsigned long)config->max_memory_mb * 1024UL * 1024UL;
#if defined(_MSC_VER)
    sprintf_s(mem_buf, sizeof(mem_buf), "max-wasm-stack=" SANDBOX_ULONG_FMT,
              bytes);
    sprintf_s(linear_mem_buf, sizeof(linear_mem_buf),
              "max-memory-size=" SANDBOX_ULONG_FMT, bytes);
#else
    sprintf(mem_buf, "max-wasm-stack=" SANDBOX_ULONG_FMT, bytes);
    sprintf(linear_mem_buf, "max-memory-size=" SANDBOX_ULONG_FMT, bytes);
#endif
    wasm_argv[current_arg++] = (char *)"-O";
    wasm_argv[current_arg++] = mem_buf;
    wasm_argv[current_arg++] = (char *)"-O";
    wasm_argv[current_arg++] = linear_mem_buf;
  }

  if (config->max_cpu_percent > 0) {
    fprintf(stderr, "[libmountsandbox] Warning: CPU rate limiting is not "
                    "natively supported by wasmtime CLI flags.\x0a");
  }

  if (config->drop_privileges) {
    fprintf(stderr, "[libmountsandbox] Info: Wasmtime is inherently "
                    "unprivileged via WASI capabilities.\x0a");
  }

  if (config->denied_syscalls) {
    fprintf(stderr, "[libmountsandbox] Info: WASI inherently denies all host "
                    "syscalls not explicitly mapped.\x0a");
  }

  if (config->env_vars) {
    size_t e;
    for (e = 0; e < config->env_count; e++) {
      wasm_argv[current_arg++] = (char *)"--env";
      wasm_argv[current_arg++] = (char *)config->env_vars[e];
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
      size_t vlen = strlen(config->mounts[m].dir) + 32;
      char *vstr = NULL;
      rc = sandbox_alloc(vlen, &raw_ptr);
      if (rc != SANDBOX_SUCCESS) {
        goto cleanup;
      }
      vstr = (char *)raw_ptr;
      if (config->mounts[m].read_only) {
        fprintf(stderr, "[libmountsandbox] Warning: Wasmtime CLI --dir does "
                        "not natively enforce read-only mounts in all "
                        "versions.\x0a");
      }
#if defined(_MSC_VER)
      sprintf_s(vstr, vlen, "%s::/workspace" SANDBOX_ULONG_FMT "%s",
                config->mounts[m].dir, (unsigned long)m,
                config->mounts[m].read_only ? "::ro" : "");
#else
      sprintf(vstr, "%s::/workspace" SANDBOX_ULONG_FMT "%s",
              config->mounts[m].dir, (unsigned long)m,
              config->mounts[m].read_only ? "::ro" : "");
#endif
      vstr_array[allocated_mounts++] = vstr;
      wasm_argv[current_arg++] = (char *)"--dir";
      wasm_argv[current_arg++] = vstr;
    }
  }

  for (i = 0; i < argc; i++) {
    wasm_argv[current_arg++] = argv[i];
  }
  wasm_argv[current_arg] = NULL;

  rc = sandbox_spawn_and_wait("wasmtime", wasm_argv, config, out_fp, err_fp,
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
  if (wasm_argv) {
    free(wasm_argv);
  }
  return rc;
}

/**
 * @brief Executes a command in the sandbox asynchronously.
 * @param config Sandbox configuration.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @param out_process Pointer to receive the process handle.
 * @return SANDBOX_ERR_UNSUPPORTED as async is not yet implemented for wasmtime.
 */
static sandbox_error_t wasmtime_execute_async(const sandbox_config_t *config,
                                              int argc, char **argv,
                                              sandbox_process_t **out_process) {
  if (!config || argc < 0 || !argv) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  fprintf(stderr, "[libmountsandbox] Async execution is a work in progress for "
                  "wasmtime. Falling back to sync.\x0a");
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
static sandbox_error_t wasmtime_wait_process(sandbox_process_t *process,
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
static sandbox_error_t wasmtime_free_process(sandbox_process_t *process) {
  if (process) {
    free(process);
  }
  return SANDBOX_SUCCESS;
}

/**
 * @brief Cleans up the engine resources.
 * @return SANDBOX_SUCCESS on completion.
 */
static sandbox_error_t wasmtime_cleanup(void) { return SANDBOX_SUCCESS; }

/**
 * @brief The Wasmtime sandbox engine export.
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
