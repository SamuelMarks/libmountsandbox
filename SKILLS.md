# Sandbox Capabilities & "Skills"

`libmountsandbox` harmonizes varied OS and container isolation architectures into a single strict C89 API. This document outlines the isolation "skills" supported and their degradation paths per platform.

## Isolation Matrix

| Capability | Linux Native (`bwrap`) | macOS Native (`sandbox-exec`) | Windows Native (Jobs / AppContainer) | Container Engines (`docker`/`podman`/`gvisor`) | Wasmtime (`wasmtime`) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Filesystem / Mounts** | Isolated via Namespaces (`--unshare-all`, `--bind`) | Isolated via escaped Seatbelt SBPL Profiles | Job Object Limits + AppContainer Config | Isolated via Volume Maps (`-v`) | WASI Directory Preopens (`--dir`) |
| **Read-Only Mounts** | Yes (`--ro-bind`) | Yes (`allow file-read*`, `deny file-write*`) | Partial (Config & Warning) | Yes (`:ro`) | Yes (`::ro`) |
| **Network Disabling** | Yes (Unshared network namespace unless `--share-net`) | Yes (`(deny network*)`) | Partial (Config & Warning) | Yes (`--network none`) | Yes (`-S inherit-network=y` omitted) |
| **Timeouts & Reaping** | Yes (Process group `setpgid` + `kill(-pid, SIGKILL)`) | Yes (Process group `setpgid` + `kill(-pid, SIGKILL)`) | Yes (`WaitForSingleObject` + `TerminateProcess`) | Yes (`--pids-limit 256` + Timeout Reaper) | Yes (Timeout Reaper) |
| **Memory Limits** | Yes (`setrlimit(RLIMIT_AS)`) | Yes (`setrlimit(RLIMIT_AS)`) | Yes (`sandbox_configure_job_limits` `process_memory_bytes`) | Yes (`--memory`) | Yes (`-O max-memory-size` & `max-wasm-stack`) |
| **CPU Limits** | Partial (Warning without Cgroups v2) | Partial (Warning) | Yes (`sandbox_configure_job_limits` `cpu_rate_percent`) | Yes (`--cpus`) | Partial (Warning) |
| **Privilege Drops** | Yes (`--uid`/`--gid` + `setgid`/`setuid`) | Yes (`setgid`/`setuid`) | Partial (Config) | Yes (`-u UID:GID` + `no-new-privileges`) | Inherently Unprivileged (WASI) |
| **Syscall Filtering** | Approximate (`--cap-drop`) + Warning | Partial (Warning) | Partial (Warning) | `--cap-drop` + `--security-opt seccomp=...` | Inherently Capability-Scoped (WASI) |

## Future & Extensible Isolation Primitives
* **Linux Landlock LSM & Seccomp-BPF:** Kernel-native unprivileged filesystem (`landlock_create_ruleset`) and syscall (`SECCOMP_SET_MODE_FILTER`) sandboxing.
* **BSD Jails, Capsicum & OpenBSD `pledge`/`unveil`:** Native process capability mode (`cap_enter`), filesystem visibility (`unveil`), and syscall promises (`pledge`).
* **MicroVMs (Firecracker / Kata / Apple Virtualization.framework):** Hardware-virtualized KVM and Hypervisor.framework execution backends.

## Fallback Philosophy
If an isolation feature (like Syscall Filtering on macOS or network bandwidth shaping without root netlink) cannot be performed natively in strictly portable C89, `libmountsandbox` emits a visible `stderr` warning stating the platform limitation and proceeds with the rest of the isolation config.
