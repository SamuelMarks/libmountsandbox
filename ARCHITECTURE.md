# Architecture of libmountsandbox

`libmountsandbox` is built around a unified struct abstraction that sits entirely in C89, translating configuration intents into platform-specific isolation implementations. 

## The Core Abstraction Layer
The abstraction is managed via two core structures defined in `src/sandbox.h`:
1. `sandbox_config_t`: A generic declarative struct describing *how* a process should be isolated (mounts, limits, timeouts, networking, etc.).
2. `sandbox_engine_t`: A function-pointer vtable (`init`, `execute`, `cleanup`) implemented by individual engines.

This design decouples the user's intent from the OS's implementation of isolation.

## Engine Implementations

### 1. Native Engine (`engine_native.c`)
The Native engine leverages built-in, dependency-free OS primitives to isolate processes.

* **macOS:** Uses `sandbox-exec` (Seatbelt). The engine dynamically generates a Scheme profile string allocating `(allow file-write* (subpath ...))` policies exclusively for writable mounts, while blanket-denying `(deny file-write*)` as a baseline.
* **Linux:** Uses `bwrap` (Bubblewrap) to create unprivileged user, mount, and PID namespaces. The engine dynamically calculates `--bind` and `--ro-bind` parameters, sets `RLIMIT_AS` for memory limits, and proxies Syscall denials to `--cap-drop`.
* **Windows:** Uses **Job Objects** (`SetInformationJobObject`). The engine creates a restricted Job Object targeting `JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION`, `JOB_OBJECT_LIMIT_ACTIVE_PROCESS` (to prevent fork bombs), and sets memory limits via `ProcessMemoryLimit`.

### 2. Docker Engine (`engine_docker.c`)
Acts as a universal fallback containerization engine.
It generates a highly restrictive `docker run --rm` command. Directory mounts are mapped via `-v`, memory/CPU limits are mapped to `--memory` and `--cpus`, and privilege drops map to `-u`.

### 3. Podman Engine (`engine_podman.c`)
Acts as a daemonless, drop-in alternative to the Docker engine. 
It uses an identical translation mechanism for commands, mapping intents to `podman run --rm` for environments that restrict Docker daemon usage.

### 4. gVisor Engine (`engine_gvisor.c`)
Acts as a high-security containerization engine. It leverages Docker under the hood but injects the `--runtime=runsc` parameter to execute the payload within gVisor's userspace kernel, significantly reducing the attack surface against the host.

### 5. Wasmtime Engine (`engine_wasmtime.c`)
Acts as a direct executor for WebAssembly (`.wasm`) binaries. It maps the standard libmountsandbox intents (directory mounts, environment variables, capabilities) directly into WASI configurations passed to the `wasmtime` CLI tool, fully bypassing OS-level sandboxing in favor of WASM's default-deny security model.

### 6. AppContainer Engine (`engine_appcontainer.c`)
Acts as a Windows-native high-security execution layer. Built strictly in C89, this engine conditionally attempts to invoke undocumented or late-bound DLL entry points inside `userenv.dll` and `kernel32.dll` via `LoadLibraryA` / `GetProcAddress`. It injects `MSB_SECURITY_CAPABILITIES` attributes into `EXTENDED_STARTUPINFO_PRESENT` context bounds, mapping executions strictly into AppContainers rather than standard Job Objects. Provides silent failure or soft stubs on MacOS/Linux.

### Execution Timeouts
Due to C89's lack of threading and high-resolution async timers, timeouts are implemented using cross-platform asynchronous polling:
* **POSIX (macOS / Linux):** Utilizes `waitpid(..., WNOHANG)` combined with `select()` spanning 100ms microsecond intervals. If the target exceeds the timeout, `SIGKILL` is issued and `124` is returned.
* **Windows:** Utilizes `WaitForSingleObject` with precise millisecond resolution, triggering `TerminateProcess` upon `WAIT_TIMEOUT`.

### File Descriptor Redirection
To bypass pipe-buffering deadlocks (the POSIX 64KB pipe limit), `libmountsandbox` routes stdout/stderr using `tmpfile()`.
* **POSIX:** After `fork()` but before `execvp()`, the engine issues `dup2(fileno(tmp_fp), STDOUT_FILENO)`.
* **Windows (Native):** Configures `STARTUPINFO` with `STARTF_USESTDHANDLES` and binds file descriptors converted to HANDLEs via `_get_osfhandle`.
* **Windows (Docker):** Uses `_dup` and `_dup2` to redirect file streams inside the parent scope temporarily during the `_spawnvp` execution.
Once the process resolves, the temporary files are read fully into dynamically allocated C-string buffers.
