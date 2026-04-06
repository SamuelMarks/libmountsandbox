# Usage Guide

`libmountsandbox` provides a Command Line Interface (CLI), a C API, a Python FFI API, a TypeScript FFI API, a Go FFI API, a Rust FFI API, a Swift FFI API, a Kotlin FFI API, a Java FFI API, and a Ruby FFI API.

## Command Line Interface (CLI)

The CLI binary is named `mountsandbox`. All configuration options can be provided either via CLI flags or equivalent environment variables. CLI flags take precedence.

```text
Usage: mountsandbox [OPTIONS] [--] <command> [args...]

Engines:
  --engine=native   (Default) Uses macOS Seatbelt, Linux bwrap, or Windows Job Objects.
  --engine=docker   Uses the local Docker daemon.
  --engine=dummy    Does not execute, used for tests.

Isolation Options:
  --no-network             Disables network access for the process.
  --mount=DIR              Mounts a directory as read-write.
  --ro-mount=DIR           Mounts a directory as read-only.
  --env=KEY=VALUE          Injects an environment variable.
  --drop-privs             Drops to a restricted 'nobody' user namespace.
  --uid=UID                Drops privileges to a specific UID.
  --gid=GID                Drops privileges to a specific GID.

Resource Options:
  --timeout=SECS           Kills the process if it runs longer than SECS seconds.
  --memory-mb=MB           Restricts RAM usage to MB Megabytes.
  --cpu-pct=PCT            Restricts CPU usage (100 = 1 core).
  --deny-syscall=SYSCALL   Drops a specific capability / capability-group.

Environment Variables:
  All long options have an equivalent environment variable using the prefix MOUNTSANDBOX_
  and converting dashes to underscores (e.g., MOUNTSANDBOX_NO_NETWORK, MOUNTSANDBOX_ENGINE).
  For options that accept multiple values (like --mount, --env), provide a comma-separated
  list (e.g., MOUNTSANDBOX_MOUNT="/tmp,/var/log").
```

## C Library API

```c
#include "sandbox.h"
#include <stdio.h>

int main(void) {
    sandbox_config_t config = {0}; // Initialize all to 0/NULL
    sandbox_mount_t mounts[1];
    const char *envs[1];
    
    // Configure mounts and environments
    mounts[0].dir = "/tmp";
    mounts[0].read_only = 0;
    
    envs[0] = "FOO=bar";
    
    config.mounts = mounts;
    config.mount_count = 1;
    config.env_vars = envs;
    config.env_count = 1;
    
    config.timeout_secs = 5;
    config.disable_network = 1;
    
    sandbox_engine_t *engine = get_sandbox_engine("native");
    engine->init();
    
    char *cmd[] = {"ls", "-la", NULL};
    int status = engine->execute(&config, 2, cmd);
    
    engine->cleanup();
    return status;
}
```

## Python FFI Binding

The library compiles a shared object (`libmountsandbox.so`/`dylib`/`dll`) which is callable via Python's `ctypes`.

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

The library can be accessed safely in Rust using the provided FFI bindings.

```rust
use mountsandbox::{LibMountSandbox, ExecuteConfig};

fn main() {
    let sandbox = LibMountSandbox::new();

    // Easy execution
    let status = sandbox.execute("native", &["echo", "hello world"], None).unwrap();
    println!("Status: {}", status);
}
```

## Swift FFI Binding

The library can be accessed safely in Swift using the provided Swift Package.

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

The library integrates cleanly into Kotlin using JNA.

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

The library integrates cleanly into Ruby using the `ffi` gem.

```ruby
require_relative 'bindings/sandbox'

sandbox = LibMountSandbox::SandboxWrapper.new
status = sandbox.execute("native", ["echo", "hello world"])
puts "Command exited with status: #{status}"
```
