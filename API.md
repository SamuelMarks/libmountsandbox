# API Reference

The `sandbox.h` header defines the strict C89 types used to interact with the engine.

## Struct: `sandbox_mount_t`
Represents a single filesystem mount context.
* `const char *dir`: Path to the directory on the host.
* `int read_only`: Boolean flag (1=ro, 0=rw).

## Struct: `sandbox_config_t`
The configuration intent. All pointers should be managed (allocated/freed) by the caller.

* `const sandbox_mount_t *mounts`: Array of mounts.
* `size_t mount_count`: Length of the mounts array.
* `int disable_network`: Boolean to unshare the network namespace.
* `const char **env_vars`: Array of `KEY=VALUE` string environment variables.
* `size_t env_count`: Length of env_vars.
* `unsigned int timeout_secs`: Absolute execution timeout in seconds.
* `char **stdout_buffer`: Pointer to receive the allocated stdout buffer string. Caller must `free()` if populated.
* `size_t *stdout_size`: Populated with the byte length of `stdout_buffer`.
* `char **stderr_buffer`: Pointer to receive the allocated stderr buffer string. Caller must `free()` if populated.
* `size_t *stderr_size`: Populated with the byte length of `stderr_buffer`.
* `unsigned int max_memory_mb`: Hard limit on virtual memory (RLIMIT_AS).
* `unsigned int max_cpu_percent`: Hard limit on CPU scheduling.
* `int drop_privileges`: Boolean to trigger user namespaces/uid swapping.
* `unsigned int target_uid`: specific UID.
* `unsigned int target_gid`: specific GID.
* `const char **denied_syscalls`: Array of capability/syscall strings to drop.
* `size_t denied_syscall_count`: Length of denied_syscalls.
* `const char *seccomp_profile_path`: Optional path to a Seccomp BPF profile.
* `const char *apparmor_profile`: Optional name of an AppArmor profile.
* `int use_pty`: Boolean flag (1=true, 0=false) to allocate a pseudo-terminal (PTY) for the sandbox. Merges stderr into stdout.
* `unsigned int max_network_mbps`: Maximum network bandwidth in Mbps. 0 means unlimited.

## Struct: `sandbox_engine_t`
The Engine abstract table. 
* `const char *engine_name`: Engine short identifier.
* `const char *description`: Human-readable description.
* `int (*init)(void)`: Prepares the engine. Returns 0 on success.
* `int (*execute)(const sandbox_config_t *config, int argc, char **argv)`: Main blocking execution hook. Returns process exit code, or -1 on fatal failure.
* `sandbox_process_t* (*execute_async)(const sandbox_config_t *config, int argc, char **argv)`: Non-blocking execution hook returning an opaque handle.
* `int (*wait_process)(sandbox_process_t *process, int *exit_status)`: Polls an async process handle for completion.
* `void (*free_process)(sandbox_process_t *process)`: Frees the process handle.
* `void (*cleanup)(void)`: Resource cleanup hook.

## Function: `get_sandbox_engine`
```c
int get_sandbox_engine(const char *name, sandbox_engine_t **engine_out);
```
Retrieves a pointer to the global engine singleton via the `engine_out` parameter. Returns `0` on success.
