libmountsandbox
===============

[![License: CC0-1.0](https://licensebuttons.net/l/zero/1.0/80x15.png)](http://creativecommons.org/publicdomain/zero/1.0/)
[![Doc Coverage](https://img.shields.io/badge/docs-100%25-brightgreen.svg)](#)
[![Test Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen.svg)](#)

**libmountsandbox** is a highly portable, strictly C89-compliant library and CLI tool for executing untrusted commands within isolated, sandboxed environments.

By abstracting OS and container-based isolation technologies into a single, unified C89 interface with explicit `sandbox_error_t` enum error percolation, `libmountsandbox` provides a clean "write-once, sandbox-anywhere" execution wrapper.

## Key Features

* **100% C89 Compliant:** Compatible with legacy and modern toolchains alike (GCC, Clang, AppleClang, MSVC, MinGW, OpenWatcom) under strict `-std=c89 -pedantic -Wall -Wextra -Werror` / `/W4 /WX` flags.
* **Explicit Error Percolation:** All functions return a unified `sandbox_error_t` enum annotated with `NO_DISCARD`.
* **Multi-Engine Support:** Native OS sandboxing (`native`), Docker (`docker`), Podman (`podman`), gVisor (`gvisor`), Wasmtime (`wasmtime`), Windows AppContainer (`appcontainer`), and a test engine (`dummy`).
* **Granular Mounts:** Read-write and read-only directory mounting.
* **Resource & Security Controls:** Execution timeouts with 100ms polling, environment variable injection, container memory/CPU limits, UID/GID privilege dropping, capability/syscall dropping, Seccomp/AppArmor profile attachment, and optional PTY allocation.
* **Stream Capture:** Deadlock-free `stdout` and `stderr` in-memory buffer capture backed by temporary file streams.
* **FFI Ready:** Bindings for Python, TypeScript, Go, Rust, Swift, Kotlin, Ruby, and C# (.NET) are provided in `bindings/`.

## Platform & Engine Matrix

* **Native (`native`):** Uses `sandbox-exec` (Seatbelt) on macOS to generate dynamic Scheme profiles restricting file writes and network access, `bwrap` (Bubblewrap) with `--unshare-all` on Linux for unprivileged namespace isolation, and Job Object limit computation with direct process execution and timeout management on Windows.
* **Docker (`docker`):** Translates `sandbox_config_t` into restricted `docker run --rm` invocations with volume mounts, `--network none`, `--memory`, `--cpus`, `-u UID:GID`, `--cap-drop`, and `--security-opt`.
* **Podman (`podman`):** Daemonless, rootless container alternative translating configuration intents into `podman run --rm`.
* **gVisor (`gvisor`):** Executes Docker containers under gVisor's `runsc` userspace kernel (`--runtime=runsc`).
* **Wasmtime (`wasmtime`):** Translates mounts, stack limits, networking, and environment variables into WASI capabilities passed to `wasmtime run`.
* **AppContainer (`appcontainer`):** Windows AppContainer execution target.
* **Dummy (`dummy`):** No-op engine for unit testing and FFI verification (including async handle lifecycle testing).

## Quick Start

### Build Requirements
* CMake 3.10+
* Any C89-compliant C compiler

### Building
```bash
mkdir build
cd build
cmake ..
make
ctest --output-on-failure
```

## Usage Examples

### 1. Command Line Interface (CLI)

Options can be supplied as CLI arguments or `MOUNTSANDBOX_*` environment variables. CLI flags take precedence.

```bash
# Using CLI flags
./mountsandbox --engine=native
    --ro-mount=/etc
    --mount=/tmp
    --timeout=5
    --memory-mb=128
    --no-network
    -- cat /etc/passwd

# Using Environment Variables
MOUNTSANDBOX_ENGINE=native
MOUNTSANDBOX_RO_MOUNT=/etc
MOUNTSANDBOX_MOUNT=/tmp
MOUNTSANDBOX_TIMEOUT=5
MOUNTSANDBOX_MEMORY_MB=128
MOUNTSANDBOX_NO_NETWORK=1
./mountsandbox -- cat /etc/passwd
```

### 2. C Library API (Strict C89)
```c
#include "sandbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

NO_DISCARD static sandbox_error_t run_command(int *out_status) {
  sandbox_config_t config;
  sandbox_mount_t mounts[1];
  sandbox_engine_t *engine = NULL;
  sandbox_error_t rc;
  sandbox_error_t cleanup_rc;
  char *cmd[4];

  if (!out_status) {
    return SANDBOX_ERR_INVALID_ARG;
  }

  memset(&config, 0, sizeof(config));
  mounts[0].dir = "/tmp";
  mounts[0].read_only = 0;

  cmd[0] = (char *)"ls";
  cmd[1] = (char *)"-la";
  cmd[2] = (char *)"/tmp";
  cmd[3] = NULL;

  config.mounts = mounts;
  config.mount_count = 1;
  config.timeout_secs = 5;
  config.disable_network = 1;

  rc = get_sandbox_engine("native", &engine);
  if (rc != SANDBOX_SUCCESS) {
    return rc;
  }

  rc = engine->init();
  if (rc != SANDBOX_SUCCESS) {
    return rc;
  }

  rc = engine->execute(&config, 3, cmd, out_status);
  cleanup_rc = engine->cleanup();
  if (rc == SANDBOX_SUCCESS && cleanup_rc != SANDBOX_SUCCESS) {
    rc = cleanup_rc;
  }

  return rc;
}

int main(void) {
  int status = 0;
  sandbox_error_t rc;

  rc = run_command(&status);
  if (rc != SANDBOX_SUCCESS) {
    fprintf(stderr, "Execution failed with sandbox_error_t: %d\n", (int)rc);
    return EXIT_FAILURE;
  }

  return status;
}
```

### 3. Python FFI Binding
`libmountsandbox` builds a shared library (`libmountsandbox.dylib` / `.so` / `mountsandbox.dll`) callable via Python's `ctypes`.

```python
from bindings.sandbox import LibMountSandbox

sandbox = LibMountSandbox(lib_path="./build/libmountsandbox.dylib")
status = sandbox.execute("native", ["echo", "hello world"])
print(f"Command exited with status: {status}")
```

### 4. TypeScript FFI Binding
Node.js bindings are available using `koffi`.

```typescript
import { LibMountSandbox } from './bindings/sandbox';

const sandbox = new LibMountSandbox("./build/libmountsandbox.so");
const status = sandbox.execute("native", ["echo", "hello world"]);
console.log(`Command exited with status: ${status}`);
```

### 5. Go FFI Binding
Go bindings are provided natively via `cgo`.

```go
package main

import (
	"fmt"
	sandbox "github.com/libmountsandbox/bindings"
)

func main() {
	sb := sandbox.NewLibMountSandbox("./build/libmountsandbox.so")
	status, err := sb.Execute("native", []string{"echo", "hello world"}, nil)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Command exited with status: %d\n", status)
}
```

### 6. Rust FFI Binding
Rust bindings are provided using safe wrappers around raw FFI calls in `bindings/rust`.

```rust
use mountsandbox::{LibMountSandbox, SandboxConfig};

fn main() {
    let sandbox = LibMountSandbox::new();
    let config = SandboxConfig::default();
    let status = sandbox
        .execute("native", &["echo", "hello world"], Some(&config))
        .unwrap();
    println!("Command exited with status: {}", status);
}
```

### 7. Swift FFI Binding
Swift bindings are provided as a Swift Package in `bindings/swift`.

```swift
import MountSandbox

let sandbox = LibMountSandbox()
let status = try sandbox.execute(engineName: "native", commandArgs: ["echo", "hello world"])
print("Command exited with status: \(status)")
```

### 8. Kotlin FFI Binding
Kotlin bindings are provided as a Gradle project utilizing JNA in `bindings/kotlin`.

```kotlin
import mountsandbox.Sandbox

fun main() {
    val sandbox = Sandbox()
    val status = sandbox.execute("native", listOf("echo", "hello world"))
    println("Command exited with status: $status")
}
```

### 9. Ruby FFI Binding
Ruby bindings are provided utilizing the `ffi` gem in `bindings/sandbox.rb`.

```ruby
require_relative 'bindings/sandbox'

sandbox = LibMountSandbox::SandboxWrapper.new
status = sandbox.execute("native", ["echo", "hello world"])
puts "Command exited with status: #{status}"
```

### 10. C# (.NET) FFI Binding
C# bindings are provided in `bindings/csharp` using P/Invoke.

```csharp
using System;
using MountSandbox;

class Program
{
    static void Main()
    {
        using var sandbox = new Sandbox("native");
        ExecutionResult res = sandbox.Execute(new[] { "echo", "hello world" });
        Console.WriteLine($"Command exited with status: {res.ExitCode}");
    }
}
```

## Documentation

For deep-dive documentation, please refer to the following guides:
1. [ARCHITECTURE.md](ARCHITECTURE.md) - System design, engine translation details, and C89 execution/stream architecture.
2. [USAGE.md](USAGE.md) - Full CLI options, C89 API, and language FFI usage guides.
3. [API.md](API.md) - Deep dive into the `sandbox.h` C89 structs, enums, and functions.
4. [SKILLS.md](SKILLS.md) - Detailed breakdown of isolation capabilities and platform support matrix.
