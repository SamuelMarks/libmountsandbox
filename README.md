libmountsandbox
===============

[![License: CC0-1.0](https://licensebuttons.net/l/zero/1.0/80x15.png)](http://creativecommons.org/publicdomain/zero/1.0/)

**libmountsandbox** is a highly portable, strictly C89-compliant library and CLI tool for executing untrusted commands within isolated, sandboxed environments. 

By abstracting various underlying OS and container-based isolation technologies into a single, unified C89 interface, `libmountsandbox` provides a robust "write-once, sandbox-anywhere" execution wrapper.

## Key Features

* **100% C89 Compliant:** Compatible with deep-legacy and modern toolchains alike (GCC, Clang, MSVC 2005, MSVC 2026, OpenWatcom).
* **Multi-Engine Support:** Native OS sandboxes (macOS, Linux, Windows), Docker, Podman, gVisor, Wasmtime, and a Dummy/test engine.
* **Granular Mounts:** Read-write and read-only directory mounting.
* **Resource Limits:** Hard limits on memory usage and CPU core percentages.
* **Execution Control:** Precise millisecond-polled timeouts, environment variable stripping/injection, network bandwidth shaping (Mbps), and non-blocking asynchronous execution.
* **Privilege Dropping:** Unprivileged User Namespaces and UID/GID switching.
* **Syscall Filtering:** Seccomp (BPF via bwrap / JSON via Docker) and AppArmor integration.
* **Extensible Output:** Stdout and Stderr in-memory buffer capture API.
* **Interactive PTY:** Optional pseudo-terminal allocation for interactive sandboxing.
* **FFI Ready:** Bindings for Python, TypeScript, Go, Rust, Swift, Kotlin, Java, Ruby, and C# (.NET) are provided out-of-the-box.

## Platform Support Matrix

The default **Native** engine leverages built-in, dependency-free OS primitives, falling back to **Docker** where requested:

* **macOS:** Uses `sandbox-exec` (Seatbelt) to generate dynamic Scheme profiles.
* **Linux:** Uses `bwrap` (Bubblewrap) for unprivileged user, mount, and PID namespaces.
* **Windows:** Uses **Job Objects** (via `native`) to impose process restrictions, or the new strict **AppContainers** (via `appcontainer`) for maximum GUI/FS isolation.
* **Universal:** A **Docker** engine translates configuration intents into highly restricted `docker run` parameters. A **Podman** engine is also available as a drop-in, daemonless alternative using `podman run`. A **gVisor** engine is available for stronger isolation using a userspace kernel (`runsc`). A **Wasmtime** engine translates intents to WASI capabilities for running WebAssembly modules directly from C.

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

Options can be supplied as CLI arguments or environment variables. CLI flags take precedence.

```bash
# Using CLI flags
./mountsandbox --engine=native \
    --ro-mount=/etc \
    --mount=/tmp \
    --timeout=5 \
    --memory-mb=128 \
    --no-network \
    -- cat /etc/passwd

# Using Environment Variables
MOUNTSANDBOX_ENGINE=native \
MOUNTSANDBOX_RO_MOUNT=/etc \
MOUNTSANDBOX_MOUNT=/tmp \
MOUNTSANDBOX_TIMEOUT=5 \
MOUNTSANDBOX_MEMORY_MB=128 \
MOUNTSANDBOX_NO_NETWORK=1 \
./mountsandbox -- cat /etc/passwd
```

### 2. C Library API
```c
#include "sandbox.h"

int main(void) {
    sandbox_config_t config = {0}; // Initialize all to 0/NULL
    sandbox_mount_t mounts[1] = {{"/tmp", 0}}; // Read-write mount
    
    config.mounts = mounts;
    config.mount_count = 1;
    config.timeout_secs = 5;
    config.disable_network = 1;
    
    sandbox_engine_t *engine = get_sandbox_engine("native");
    engine->init();
    
    char *cmd[] = {"ls", "-la", "/tmp", NULL};
    int status = engine->execute(&config, 3, cmd);
    
    engine->cleanup();
    return status;
}
```

### 3. Python FFI Binding
`libmountsandbox` provides a shared object (`libmountsandbox.dylib` / `.so` / `.dll`) easily callable via Python's `ctypes`.

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
Rust bindings are provided using safe wrappers around raw FFI calls. Ensure you have the library compiled and linked.

```rust
use mountsandbox::{LibMountSandbox, ExecuteConfig};

fn main() {
    let sandbox = LibMountSandbox::new();
    let status = sandbox.execute("native", &["echo", "hello world"], None).unwrap();
    println!("Command exited with status: {}", status);
}
```

## Documentation

For deep-dive documentation, please refer to the following guides:
1. [ARCHITECTURE.md](ARCHITECTURE.md) - System design, cross-platform mapping, and C89 constraints.
2. [USAGE.md](USAGE.md) - Full CLI options, C API, Python, and TypeScript FFI usage guides.
3. [API.md](API.md) - Deep dive into the `sandbox.h` C structs and functions.
4. [SKILLS.md](SKILLS.md) - Detailed breakdown of isolation capabilities and platform support matrix.

### 7. Swift FFI Binding
Swift bindings are provided as a Swift Package that safely wraps the C library.

```swift
import MountSandbox

let sandbox = LibMountSandbox()
let status = try sandbox.execute(engineName: "native", commandArgs: ["echo", "hello world"])
print("Command exited with status: \(status)")
```

### 8. Kotlin FFI Binding
Kotlin bindings are provided as a Gradle project utilizing JNA for safe cross-platform C interop.

```kotlin
import mountsandbox.Sandbox

fun main() {
    val sandbox = Sandbox()
    val status = sandbox.execute("native", listOf("echo", "hello world"))
    println("Command exited with status: $status")
}
```

### 9. Ruby FFI Binding
Ruby bindings are provided utilizing the `ffi` gem for safe cross-platform C interop.

```ruby
require_relative 'bindings/sandbox'

sandbox = LibMountSandbox::SandboxWrapper.new
status = sandbox.execute("native", ["echo", "hello world"])
puts "Command exited with status: #{status}"
```
