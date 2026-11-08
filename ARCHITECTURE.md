# Architecture of libmountsandbox

`libmountsandbox` is built around a unified struct abstraction that sits entirely in strict ISO C90 (C89), translating configuration intents into platform-specific isolation implementations with universal `sandbox_error_t` error percolation.

## The Core Abstraction Layer
The abstraction is managed via two core structures defined in `src/sandbox.h`:
1. `sandbox_config_t`: A generic declarative struct describing *how* a process should be isolated (mounts, limits, timeouts, networking, stream capture, etc.).
2. `sandbox_engine_t`: A function-pointer vtable (`init`, `execute`, `execute_async`, `wait_process`, `free_process`, `cleanup`) implemented by individual engines, where every hook returns `sandbox_error_t`.

This design decouples the user's intent from the OS or runtime implementation of isolation.

## Engine Implementations

### 1. Native Engine (`engine_native.c`)
The Native engine leverages built-in OS primitives and standard tools to isolate processes:

* **macOS:** Uses `sandbox-exec` (Seatbelt). The engine sanitizes mount paths via `sandbox_escape_sbpl_path()` and dynamically generates a Scheme profile string allocating `(allow file-read* (subpath "..."))` for read-only mounts and `(allow file-write* (subpath "..."))` for writable mounts, while blanket-denying `(deny file-write*)` as a baseline and `(deny network*)` when networking is disabled.
* **Linux:** Uses `bwrap` (Bubblewrap) with `--unshare-all` and `--die-with-parent` to create unprivileged user, mount, PID, IPC, UTS, and cgroup namespaces. The engine dynamically calculates `--bind` and `--ro-bind` parameters, passes `--share-net` unless network access is disabled, maps privilege drops to `--uid`/`--gid`, and proxies syscall/capability denials to `--cap-drop`.
* **Windows:** Computes Job Object limits via `sandbox_configure_job_limits()` (`SANDBOX_JOB_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`, `SANDBOX_JOB_LIMIT_ACTIVE_PROCESS`, `SANDBOX_JOB_LIMIT_KILL_ON_JOB_CLOSE`, `SANDBOX_JOB_LIMIT_PROCESS_MEMORY`, and CPU rate control) without including `<windows.h>`, and executes the target binary via `sandbox_spawn_and_wait()`.

### 2. Docker Engine (`engine_docker.c`)
Acts as a universal containerization engine.
It generates a restrictive `docker run --rm --pids-limit 256` command. Directory mounts are mapped via `-v <dir>:/workspace<N>[:ro]`, memory/CPU limits are mapped to `--memory` and `--cpus`, Seccomp/AppArmor profiles map to `--security-opt`, and privilege drops map to `--security-opt no-new-privileges` and `-u <uid>:<gid>`.

### 3. Podman Engine (`engine_podman.c`)
Acts as a daemonless, rootless drop-in alternative to the Docker engine.
It uses an identical translation mechanism for commands, mapping intents to `podman run --rm --pids-limit 256` for environments that restrict Docker daemon usage.

### 4. gVisor Engine (`engine_gvisor.c`)
Acts as a high-security containerization engine. It leverages Docker under the hood (`docker run --runtime=runsc --rm --pids-limit 256`) to execute the payload within gVisor's userspace kernel, significantly reducing the host kernel attack surface.

### 5. Wasmtime Engine (`engine_wasmtime.c`)
Acts as a direct executor for WebAssembly (`.wasm`) binaries. It maps `libmountsandbox` intents (directory mounts via `--dir <dir>::/workspace<N>[::ro]`, environment variables via `--env`, memory/stack limits via `-O max-wasm-stack=... -O max-memory-size=...`, and network inheritance via `-S inherit-network=y`) directly into WASI configurations passed to `wasmtime run`.

### 6. AppContainer Engine (`engine_appcontainer.c`)
Acts as a Windows-targeted execution layer built strictly in C89 without `<windows.h>`. It computes Job Object quota structures via `sandbox_configure_job_limits()`, constructs a quoted command-line buffer, emits structured diagnostics for unsupported POSIX-specific options, and dispatches execution via `sandbox_spawn_and_wait()`.

### 7. Dummy Engine (`engine_dummy.c`)
Acts as a no-op test and FFI verification backend, supporting both synchronous (`execute`) and asynchronous (`execute_async`, `wait_process`, `free_process`) execution lifecycles.

## Shared Execution & Stream Architecture (`sandbox_common.c`)

### Execution Timeouts & Process Group Reaping
Due to C89's lack of standard threading and high-resolution async timers, timeouts are implemented using cross-platform polling in `sandbox_spawn_and_wait()`:
* **POSIX (macOS / Linux):** Places the child into a dedicated process group (`setpgid(0, 0)`), applies `RLIMIT_AS`, `setgid`/`setuid`, and `putenv` in the child prior to `execvp()`, and polls `waitpid(..., WNOHANG)` in the parent using `select()` at 100ms intervals. If the target exceeds the timeout, `kill(-pid, SIGKILL)` and `kill(pid, SIGKILL)` reap the entire process group and `124` is returned.
* **Windows:** Utilizes `_spawnvp` (`_P_NOWAIT` when a timeout is set) with `WaitForSingleObject` at millisecond resolution, triggering `TerminateProcess` and returning `124` upon `WAIT_TIMEOUT`.

### File Descriptor Redirection
To bypass pipe-buffering deadlocks (such as the POSIX 64KB pipe limit), `libmountsandbox` routes `stdout` and `stderr` using temporary files opened via `sandbox_open_tmpfile()` (`tmpfile()` / `tmpfile_s()`):
* **POSIX:** After `fork()` but before `execvp()`, the child issues `dup2(fileno(out_fp), STDOUT_FILENO)` and `dup2(fileno(err_fp), STDERR_FILENO)`.
* **Windows:** Uses `_dup` and `_dup2` with `_fileno()` around `_spawnvp` to redirect standard streams to the temporary file descriptors and restore the parent descriptors afterward.
Once the process terminates, the temporary files are read into dynamically allocated C-string buffers via `sandbox_read_fp_to_buffer()`.
