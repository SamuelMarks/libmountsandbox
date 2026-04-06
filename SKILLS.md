# Sandbox Capabilities & "Skills"

`libmountsandbox` attempts to harmonize extremely varied OS architectures. This document outlines the isolation "skills" supported and their degradation paths per platform.

## Isolation Matrix

| Capability | Linux Native (`bwrap`) | macOS Native (`sandbox-exec`) | Windows Native (Jobs) | Docker Engine |
| :--- | :--- | :--- | :--- | :--- |
| **Filesystem / Mounts** | Fully Isolated via Namespaces | Fully Isolated via Seatbelt Profiles | Partial (Limits start dir only) | Fully Isolated via Volume Maps |
| **Read-Only Mounts** | Yes (`--ro-bind`) | Yes (Denies file-write*) | No | Yes (`:ro`) |
| **Network Disabling** | Yes (`--unshare-net`) | Yes (`deny network*`) | No (Requires Firewall APIs) | Yes (`--network none`) |
| **Timeouts** | Yes (Select Polling + SIGKILL) | Yes (Select Polling + SIGKILL) | Yes (WaitForSingleObject) | Yes (Select/Wait + Terminate) |
| **Memory Limits** | Yes (`RLIMIT_AS`) | Yes (`RLIMIT_AS`) | Yes (`ProcessMemoryLimit`) | Yes (`--memory`) |
| **CPU Limits** | No (Requires Cgroups) | No | No (Requires Win 8+ APIs) | Yes (`--cpus`) |
| **Privilege Drops** | Yes (`--unshare-user`) | Yes (`setuid`/`setgid`) | No (Requires Token Impersonation)| Yes (`-u UID:GID`) |
| **Syscall Filtering**| Approximate (`--cap-drop`) | No | No | Approximate (`--cap-drop`) |

## Fallback Philosophy
If an isolation feature (like Syscall Filtering on macOS) cannot be performed securely and natively in strictly portable C89, `libmountsandbox` emits a visible `stderr` warning stating the platform limitation and proceeds with the rest of the isolation config. It favors a "best effort native isolation" rather than failing to boot or requiring heavy dependencies.
