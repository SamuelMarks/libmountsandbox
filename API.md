# API Reference

The `sandbox.h`, `sandbox_common.h`, and `log.h` headers define the strict C89 types, macros, and functions used to interact with `libmountsandbox`.

## Enum: `sandbox_error_t`
Error codes returned by all `libmountsandbox` functions:
* `SANDBOX_SUCCESS = 0`: Operation completed successfully.
* `SANDBOX_ERR_INVALID_ARG = 1`: Invalid or NULL argument provided.
* `SANDBOX_ERR_OUT_OF_MEMORY = 2`: Memory allocation failed (out of memory).
* `SANDBOX_ERR_NOT_FOUND = 3`: Requested sandbox engine was not found.
* `SANDBOX_ERR_UNSUPPORTED = 4`: Requested feature or platform is not supported.
* `SANDBOX_ERR_EXEC_FAILED = 5`: Sandbox command execution or OS API call failed.
* `SANDBOX_ERR_IO = 6`: Input/output or temporary stream operation failed.

## Struct: `sandbox_mount_t`
Represents a single filesystem mount context (`sandbox.h`).
* `const char *dir`: Path to the directory on the host.
* `int read_only`: Boolean flag (1=ro, 0=rw).

## Struct: `sandbox_config_t`
The configuration intent (`sandbox.h`). All input pointers should be managed (allocated/freed) by the caller.

* `const sandbox_mount_t *mounts`: Array of mounts.
* `size_t mount_count`: Length of the mounts array.
* `int disable_network`: Boolean to unshare/disable network access.
* `const char **env_vars`: Array of `KEY=VALUE` string environment variables.
* `size_t env_count`: Length of `env_vars`.
* `unsigned int timeout_secs`: Absolute execution timeout in seconds (0 means no timeout).
* `char **stdout_buffer`: Pointer to receive the allocated stdout buffer string. Caller must `free()` if populated.
* `size_t *stdout_size`: Populated with the byte length of `stdout_buffer`.
* `char **stderr_buffer`: Pointer to receive the allocated stderr buffer string. Caller must `free()` if populated.
* `size_t *stderr_size`: Populated with the byte length of `stderr_buffer`.
* `unsigned int max_memory_mb`: Hard limit on virtual memory (`RLIMIT_AS` / `--memory` / Job Object `process_memory_bytes` / `max-memory-size`).
* `unsigned int max_cpu_percent`: Hard limit on CPU scheduling (`--cpus` / Job Object `cpu_rate_percent`).
* `int drop_privileges`: Boolean to trigger user namespaces/UID swapping and `no-new-privileges`.
* `unsigned int target_uid`: Specific UID when `drop_privileges` is set.
* `unsigned int target_gid`: Specific GID when `drop_privileges` is set.
* `const char **denied_syscalls`: Array of capability/syscall strings to drop.
* `size_t denied_syscall_count`: Length of `denied_syscalls`.
* `const char *seccomp_profile_path`: Optional path to a Seccomp BPF profile.
* `const char *apparmor_profile`: Optional name of an AppArmor profile.
* `int use_pty`: Boolean flag (1=true, 0=false) to allocate a pseudo-terminal (PTY) for the sandbox.
* `unsigned int max_network_mbps`: Maximum network bandwidth in Mbps. 0 means unlimited.

## Struct: `sandbox_job_limits_t`
Computed Windows Job Object limit flags and quotas (`sandbox_common.h`):
* `unsigned long limit_flags`: Bitmask of active Job Object limit flags (`SANDBOX_JOB_LIMIT_ACTIVE_PROCESS`, `SANDBOX_JOB_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`, `SANDBOX_JOB_LIMIT_KILL_ON_JOB_CLOSE`, `SANDBOX_JOB_LIMIT_PROCESS_MEMORY`).
* `unsigned int active_process_limit`: Maximum active processes allowed in the job.
* `unsigned long process_memory_bytes`: Process virtual memory limit in bytes (0 if unlimited).
* `unsigned int cpu_rate_percent`: CPU rate control percentage (1-100, or 0 if unlimited).

## Struct: `sandbox_engine_t`
The Engine abstract vtable (`sandbox.h`).
* `const char *engine_name`: Engine short identifier (`"native"`, `"docker"`, `"podman"`, `"gvisor"`, `"wasmtime"`, `"appcontainer"`, `"dummy"`).
* `const char *description`: Human-readable description.
* `sandbox_error_t (*init)(void)`: Prepares the engine. Returns `SANDBOX_SUCCESS` on success.
* `sandbox_error_t (*execute)(const sandbox_config_t *config, int argc, char **argv, int *exit_status)`: Main blocking execution hook. Stores process exit code in `*exit_status` and returns `SANDBOX_SUCCESS` or an error enum.
* `sandbox_error_t (*execute_async)(const sandbox_config_t *config, int argc, char **argv, sandbox_process_t **out_process)`: Non-blocking execution hook outputting an opaque handle via `out_process`.
* `sandbox_error_t (*wait_process)(sandbox_process_t *process, int *exit_status)`: Polls an async process handle for completion.
* `sandbox_error_t (*free_process)(sandbox_process_t *process)`: Frees the process handle and returns `SANDBOX_SUCCESS`.
* `sandbox_error_t (*cleanup)(void)`: Resource cleanup hook.

## Functions

### Public Registry (`sandbox.h`)
* `sandbox_error_t get_sandbox_engine(const char *name, sandbox_engine_t **engine_out)`: Retrieves a pointer to the global engine singleton (`engine_native`, `engine_docker`, `engine_podman`, `engine_gvisor`, `engine_wasmtime`, `engine_appcontainer`, or `engine_dummy`) via `engine_out`.

### Common & Isolation Helpers (`sandbox_common.h`)
* `sandbox_error_t sandbox_alloc(size_t size, void **out_ptr)`: Allocates heap memory (with OOM fault-injection support when `SANDBOX_ENABLE_MOCKS` is defined).
* `sandbox_error_t sandbox_open_tmpfile(FILE **out_fp)`: Opens a temporary file stream using standard `tmpfile()` or MSVC `tmpfile_s()`.
* `sandbox_error_t sandbox_read_fp_to_buffer(FILE *fp, char **buf, size_t *size)`: Reads all content from a temporary file stream into a dynamically allocated null-terminated buffer.
* `sandbox_error_t sandbox_escape_sbpl_path(const char *raw_path, char **out_escaped)`: Escapes double quotes (`"`) and backslashes in host paths for safe macOS Seatbelt Profile Language (SBPL) inclusion.
* `sandbox_error_t sandbox_configure_job_limits(const sandbox_config_t *config, sandbox_job_limits_t *out_limits)`: Computes Windows Job Object limit parameters from a `sandbox_config_t`.
* `sandbox_error_t sandbox_spawn_and_wait(const char *bin_name, char **exec_argv, const sandbox_config_t *config, FILE *out_fp, FILE *err_fp, int *exit_status)`: Spawns an external binary with arguments, optional stream redirection, resource limits, and timeout enforcement.

### Logging (`log.h`)
* `sandbox_error_t libmountsandbox_log_debug(const char *fmt, ...)`: Outputs a formatted debug log message to `stderr` (also aliased via the `LOG_DEBUG` macro).
