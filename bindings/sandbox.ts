import koffi from 'koffi';
import * as path from 'path';

// Define the C structs
export const SandboxMount = koffi.struct('sandbox_mount_t', {
    dir: 'const char*',
    read_only: 'int'
});

export const SandboxConfig = koffi.struct('sandbox_config_t', {
    mounts: koffi.pointer(SandboxMount),
    mount_count: 'size_t',
    disable_network: 'int',
    env_vars: koffi.pointer('const char*'),
    env_count: 'size_t',
    timeout_secs: 'unsigned int',
    stdout_buffer: koffi.pointer('char*'),
    stdout_size: koffi.pointer('size_t'),
    stderr_buffer: koffi.pointer('char*'),
    stderr_size: koffi.pointer('size_t'),
    max_memory_mb: 'unsigned int',
    max_cpu_percent: 'unsigned int',
    drop_privileges: 'int',
    target_uid: 'unsigned int',
    target_gid: 'unsigned int',
    denied_syscalls: koffi.pointer('const char*'),
    denied_syscall_count: 'size_t',
    seccomp_profile_path: 'const char*',
    apparmor_profile: 'const char*',
    use_pty: 'int',
    max_network_mbps: 'unsigned int'
});

const InitProto = koffi.proto('int InitProto(void)');
const ExecuteProto = koffi.proto('int ExecuteProto(sandbox_config_t*, int, const char**)');
const CleanupProto = koffi.proto('void CleanupProto(void)');

export const SandboxEngine = koffi.struct('sandbox_engine_t', {
    engine_name: 'const char*',
    description: 'const char*',
    init: koffi.pointer(InitProto),
    execute: koffi.pointer(ExecuteProto),
    execute_async: 'void*',
    wait_process: 'void*',
    free_process: 'void*',
    cleanup: koffi.pointer(CleanupProto)
});

export class LibMountSandbox {
    private lib: koffi.IKoffiLib;
    private getSandboxEngine: any;

    constructor(libPath: string = './build/libmountsandbox.so') {
        const ext = path.extname(libPath);
        let actualPath = libPath;
        if (!ext || ext === '.so' || ext === '.dylib' || ext === '.dll') {
            const platformExt = process.platform === 'darwin' ? '.dylib' : (process.platform === 'win32' ? '.dll' : '.so');
            actualPath = libPath.replace(/\.(so|dylib|dll)$/, platformExt);
        }
        this.lib = koffi.load(actualPath);
        this.getSandboxEngine = this.lib.func('int get_sandbox_engine(const char* name, _Out_ sandbox_engine_t** engine_out)');
    }

    public execute(engineName: string, commandArgs: string[], config: any = null): number {
        let enginePtrRef = [null];
        const res = this.getSandboxEngine(engineName, enginePtrRef);
        if (res !== 0 || !enginePtrRef[0]) {
            throw new Error(`Unknown sandbox engine: ${engineName}`);
        }
        const enginePtr = enginePtrRef[0];

        const engine = koffi.decode(enginePtr, SandboxEngine);

        const init = koffi.decode(engine.init, InitProto);
        const execute = koffi.decode(engine.execute, ExecuteProto);
        const cleanup = koffi.decode(engine.cleanup, CleanupProto);

        if (init() !== 0) {
            throw new Error(`Failed to initialize engine: ${engineName}`);
        }

        let passedConfig = config;
        if (!passedConfig) {
            passedConfig = {
                mounts: null,
                mount_count: 0,
                disable_network: 0,
                env_vars: null,
                env_count: 0,
                timeout_secs: 0,
                stdout_buffer: null,
                stdout_size: null,
                stderr_buffer: null,
                stderr_size: null,
                max_memory_mb: 0,
                max_cpu_percent: 0,
                drop_privileges: 0,
                target_uid: 0,
                target_gid: 0,
                denied_syscalls: null,
                denied_syscall_count: 0,
                seccomp_profile_path: null,
                apparmor_profile: null,
                use_pty: 0,
                max_network_mbps: 0
            };
        }

        const argc = commandArgs.length;
        const argv = commandArgs;

        const status = execute(passedConfig, argc, argv);
        cleanup();
        
        return status;
    }
}
