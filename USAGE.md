# Usage Guide

`libmountsandbox` provides a Command Line Interface (CLI), a strict C89 API, and FFI bindings for Python, TypeScript, Go, Rust, Swift, Kotlin, Ruby, and C# (.NET).

## Command Line Interface (CLI)

The CLI binary is named `mountsandbox`. All configuration options can be provided either via CLI flags or equivalent environment variables. CLI flags take precedence.

```text
Usage: mountsandbox [OPTIONS] [--] <command> [args...]

General Options:
  --help                   Show this help message and exit.
  --version                Show version information and exit.

Engines:
  --engine=native          Uses macOS Seatbelt, Linux bwrap, or Windows Job Objects.
  --engine=docker          Uses the local Docker daemon.
  --engine=podman          Uses Podman rootless containers.
  --engine=gvisor          Uses Docker with the gVisor (runsc) runtime.
  --engine=wasmtime        Executes WebAssembly binaries via Wasmtime WASI.
  --engine=appcontainer    Uses Windows AppContainer isolation.
  --engine=dummy           (Default) No-op engine used for unit tests.

Isolation Options:
  --no-network             Disables network access for the process.
  --mount=DIR              Mounts a directory as read-write.
  --ro-mount=DIR           Mounts a directory as read-only.
  --env=KEY=VALUE          Injects an environment variable.
  --drop-privs             Drops to a restricted 'nobody' user namespace.
  --uid=UID                Drops privileges to a specific UID (implies --drop-privs).
  --gid=GID                Drops privileges to a specific GID (implies --drop-privs).

Resource Options:
  --timeout=SECS           Kills the process if it runs longer than SECS seconds.
  --memory-mb=MB           Restricts RAM usage to MB Megabytes.
  --cpu-pct=PCT            Restricts CPU usage (100 = 1 core).
  --deny-syscall=SYSCALL   Drops a specific capability / capability-group.

Environment Variables:
  All long options have an equivalent environment variable using the prefix MOUNTSANDBOX_
  and converting dashes to underscores (e.g., MOUNTSANDBOX_NO_NETWORK, MOUNTSANDBOX_ENGINE).
  For options that accept multiple values (like --mount, --ro-mount, --env, --deny-syscall),
  provide a comma-separated list (e.g., MOUNTSANDBOX_MOUNT="/tmp,/var/log").
```

## C Library API (Strict C89)

```c
#include "sandbox.h"
#include <stdio.h>
#include <string.h>

int main(void) {
  sandbox_config_t config;
  sandbox_mount_t mounts[1];
  const char *envs[1];
  sandbox_engine_t *engine = NULL;
  sandbox_error_t rc;
  char *cmd[3];
  int status = 0;

  memset(&config, 0, sizeof(config));

  /* Configure mounts and environments */
  mounts[0].dir = "/tmp";
  mounts[0].read_only = 0;

  envs[0] = "FOO=bar";

  config.mounts = mounts;
  config.mount_count = 1;
  config.env_vars = envs;
  config.env_count = 1;

  config.timeout_secs = 5;
  config.disable_network = 1;

  rc = get_sandbox_engine("native", &engine);
  if (rc != SANDBOX_SUCCESS) {
    return (int)rc;
  }

  rc = engine->init();
  if (rc != SANDBOX_SUCCESS) {
    return (int)rc;
  }

  cmd[0] = (char *)"ls";
  cmd[1] = (char *)"-la";
  cmd[2] = NULL;

  rc = engine->execute(&config, 2, cmd, &status);
  if (rc != SANDBOX_SUCCESS) {
    return (int)rc;
  }

  rc = engine->cleanup();
  if (rc != SANDBOX_SUCCESS) {
    return (int)rc;
  }

  return status;
}
```

## Python FFI Binding

The library compiles a shared object (`libmountsandbox.so` / `libmountsandbox.dylib` / `mountsandbox.dll`) which is callable via Python's `ctypes`.

```python
from bindings.sandbox import LibMountSandbox, SandboxConfig, SandboxMount

sandbox = LibMountSandbox(lib_path="./build/libmountsandbox.dylib")

# Easy execution
status = sandbox.execute("native", ["echo", "hello world"])
print(f"Status: {status}")
```

## TypeScript FFI Binding

The library can also be invoked natively via Node.js using `koffi`.

```typescript
import { LibMountSandbox } from './bindings/sandbox';

const sandbox = new LibMountSandbox("./build/libmountsandbox.so");

// Easy execution
const status = sandbox.execute("native", ["echo", "hello world"]);
console.log(`Status: ${status}`);
```

## Go FFI Binding

The library integrates seamlessly into Go using `cgo`.

```go
package main

import (
	"fmt"
	sandbox "github.com/libmountsandbox/bindings"
)

func main() {
	sb := sandbox.NewLibMountSandbox("./build/libmountsandbox.so")

	// Easy execution
	status, err := sb.Execute("native", []string{"echo", "hello world"}, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Status: %d\n", status)
}
```

## Rust FFI Binding

The library can be accessed safely in Rust using the provided FFI bindings in `bindings/rust`.

```rust
use mountsandbox::{LibMountSandbox, SandboxConfig};

fn main() {
    let sandbox = LibMountSandbox::new();
    let config = SandboxConfig::default();

    // Easy execution
    let status = sandbox.execute("native", &["echo", "hello world"], Some(&config)).unwrap();
    println!("Status: {}", status);
}
```

## Swift FFI Binding

The library can be accessed safely in Swift using the provided Swift Package in `bindings/swift`.

```swift
import MountSandbox

let sandbox = LibMountSandbox()

let config = SandboxConfig(
    mounts: [SandboxMount(dir: "/tmp", readOnly: false)],
    disableNetwork: true,
    timeoutSecs: 5
)

// Easy execution
let status = try sandbox.execute(
    engineName: "native",
    commandArgs: ["echo", "hello world"],
    config: config
)
print("Status: \(status)")
```

## Kotlin FFI Binding

The library integrates cleanly into Kotlin using JNA in `bindings/kotlin`.

```kotlin
import mountsandbox.Sandbox
import mountsandbox.SandboxConfig

fun main() {
    val sandbox = Sandbox()

    val config = SandboxConfig()
    config.disable_network = 1
    config.timeout_secs = 5

    // Easy execution
    val status = sandbox.execute("native", listOf("echo", "hello world"), config)
    println("Status: $status")
}
```

## Ruby FFI Binding

The library integrates cleanly into Ruby using the `ffi` gem in `bindings/sandbox.rb`.

```ruby
require_relative 'bindings/sandbox'

sandbox = LibMountSandbox::SandboxWrapper.new
status = sandbox.execute("native", ["echo", "hello world"])
puts "Command exited with status: #{status}"
```

## C# (.NET) FFI Binding

The library integrates into .NET via P/Invoke in `bindings/csharp`.

```csharp
using System;
using MountSandbox;

class Program
{
    static void Main()
    {
        using var sandbox = new Sandbox("native");
        ExecutionResult res = sandbox.Execute(new[] { "echo", "hello world" });
        Console.WriteLine($"Status: {res.ExitCode}");
    }
}
```
