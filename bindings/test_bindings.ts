import { LibMountSandbox, SandboxConfig } from './sandbox';
import koffi from 'koffi';
import * as path from 'path';
import * as os from 'os';

function main() {
    console.log("Testing TypeScript FFI Bindings...");

    let libName = 'libmountsandbox.so';
    if (os.platform() === 'darwin') {
        libName = 'libmountsandbox.dylib';
    } else if (os.platform() === 'win32') {
        libName = 'mountsandbox.dll';
    }

    const libPath = path.resolve(__dirname, "..", "build", libName);
    const sandbox = new LibMountSandbox(libPath);

    // Test 1: Dummy engine
    try {
        const statusDummy = sandbox.execute("dummy", ["echo", "test"]);
        if (statusDummy !== 0) {
            throw new Error(`Dummy engine failed with status ${statusDummy}`);
        }
        console.log("Dummy engine test passed.");
    } catch (e: any) {
        console.error("Failed to execute dummy engine:", e.message);
        process.exit(1);
    }

    // Test 2: Dummy engine with full configuration struct and buffer pointers
    try {
        const outPtr = koffi.alloc('char*', 8);
        const outSize = koffi.alloc('size_t', 8);

        const config = {
            mounts: [{ dir: '/tmp', read_only: 1 }],
            mount_count: 1,
            disable_network: 1,
            env_vars: ['TEST=1'],
            env_count: 1,
            timeout_secs: 5,
            stdout_buffer: outPtr,
            stdout_size: outSize,
            stderr_buffer: null,
            stderr_size: null,
            max_memory_mb: 128,
            max_cpu_percent: 50,
            drop_privileges: 1,
            target_uid: 1000,
            target_gid: 1000,
            denied_syscalls: ['ptrace'],
            denied_syscall_count: 1,
            seccomp_profile_path: null,
            apparmor_profile: null,
            use_pty: 0,
            max_network_mbps: 0
        };

        const statusCfg = sandbox.execute("dummy", ["echo", "hello"], config);
        if (statusCfg !== 0) {
            throw new Error(`Dummy engine with config failed with status ${statusCfg}`);
        }
        console.log("Dummy engine with config test passed.");
    } catch (e: any) {
        console.error("Failed to execute dummy engine with config:", e.message);
        process.exit(1);
    }

    console.log("All TS FFI tests passed!");
}

main();
