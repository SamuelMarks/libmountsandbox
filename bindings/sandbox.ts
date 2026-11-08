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
    env_vars: 'const char**',
    env_count: 'size_t',
    timeout_secs: 'uint',
    stdout_buffer: 'void*',
    stdout_size: 'void*',
    stderr_buffer: 'void*',
    stderr_size: 'void*',
    max_memory_mb: 'uint',
    max_cpu_percent: 'uint',
    drop_privileges: 'int',
    target_uid: 'uint',
    target_gid: 'uint',
    denied_syscalls: 'const char**',
    denied_syscall_count: 'size_t',
    seccomp_profile_path: 'const char*',
    apparmor_profile: 'const char*',
    use_pty: 'int',
    max_network_mbps: 'uint'
});

// Define function pointer prototypes
const InitCallback = koffi.proto('int InitCallback(void)');
const ExecuteCallback = koffi.proto('int ExecuteCallback(const sandbox_config_t* config, int argc, const char** argv, _Out_ int* exit_status)');
const ExecuteAsyncCallback = koffi.proto('int ExecuteAsyncCallback(const sandbox_config_t* config, int argc, const char** argv, void** out_process)');
const WaitProcessCallback = koffi.proto('int WaitProcessCallback(void* process, int* exit_status)');
const FreeProcessCallback = koffi.proto('int FreeProcessCallback(void* process)');
const CleanupCallback = koffi.proto('int CleanupCallback(void)');

export const SandboxEngine = koffi.struct('sandbox_engine_t', {
    engine_name: 'const char*',
    description: 'const char*',
    init: koffi.pointer(InitCallback),
    execute: koffi.pointer(ExecuteCallback),
    execute_async: koffi.pointer(ExecuteAsyncCallback),
    wait_process: koffi.pointer(WaitProcessCallback),
    free_process: koffi.pointer(FreeProcessCallback),
    cleanup: koffi.pointer(CleanupCallback)
});

export interface MountConfig {
    dir: string;
    read_only: number;
}

export interface ExecutionConfig {
    mounts?: MountConfig[];
    mount_count?: number;
    disable_network?: number;
    env_vars?: string[];
    env_count?: number;
    timeout_secs?: number;
    max_memory_mb?: number;
    max_cpu_percent?: number;
    drop_privileges?: number;
    target_uid?: number;
    target_gid?: number;
    denied_syscalls?: string[];
    denied_syscall_count?: number;
    seccomp_profile_path?: string | null;
    apparmor_profile?: string | null;
    use_pty?: number;
    max_network_mbps?: number;
}

export class LibMountSandbox {
    private lib: any;
    private get_sandbox_engine: any;

    constructor(libPath?: string) {
        if (!libPath) {
            let ext = '.so';
            let prefix = 'lib';
            if (process.platform === 'darwin') ext = '.dylib';
            else if (process.platform === 'win32') { ext = '.dll'; prefix = ''; }
            libPath = path.join(__dirname, '..', 'build', `${prefix}mountsandbox${ext}`);
        }
        this.lib = koffi.load(libPath);
        this.get_sandbox_engine = this.lib.func('int get_sandbox_engine(const char* name, _Out_ void** engine_out)');
    }

    public execute(engineName: string, commandArgs: string[], config?: ExecutionConfig): number {
        const engineOut: any[] = [null];
        const rc = this.get_sandbox_engine(engineName, engineOut);
        if (rc !== 0 || !engineOut[0]) {
            throw new Error(`Engine '${engineName}' not found.`);
        }

        const engine = koffi.decode(engineOut[0], SandboxEngine);

        // Decode function pointers so we can call them
        const init = koffi.decode(engine.init, InitCallback);
        const execute = koffi.decode(engine.execute, ExecuteCallback);
        const cleanup = koffi.decode(engine.cleanup, CleanupCallback);

        if (init() !== 0) {
            throw new Error(`Failed to initialize engine '${engineName}'.`);
        }

        let passedConfig: any = config;
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

        const statusOut: number[] = [0];
        const execRc = execute(passedConfig, argc, argv, statusOut);
        cleanup();

        if (execRc !== 0) {
            return -1;
        }
        return statusOut[0];
    }
}
