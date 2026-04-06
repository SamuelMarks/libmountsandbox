import Foundation
import CMountSandbox

/// Represents a single directory mount inside the sandbox.
public struct SandboxMount {
    /// The directory path on the host to mount.
    public let dir: String
    /// Boolean flag indicating if the mount is read-only.
    public let readOnly: Bool
    
    /// Initializes a new SandboxMount.
    /// - Parameters:
    ///   - dir: The directory path on the host.
    ///   - readOnly: True to mount as read-only.
    public init(dir: String, readOnly: Bool) {
        self.dir = dir
        self.readOnly = readOnly
    }
}

/// Configuration parameters for a sandbox execution.
public struct SandboxConfig {
    /// Array of mount points to expose in the sandbox.
    public let mounts: [SandboxMount]
    /// Boolean flag to disable network access in the sandbox.
    public let disableNetwork: Bool
    /// Array of environment variable strings in "KEY=VALUE" format.
    public let envVars: [String]
    /// Execution timeout in seconds. A value of 0 means no timeout.
    public let timeoutSecs: UInt32
    /// Maximum memory limit in Megabytes. 0 means no limit.
    public let maxMemoryMb: UInt32
    /// Maximum CPU limit in percent (e.g., 100 = 1 full core). 0 means no limit.
    public let maxCpuPercent: UInt32
    /// Boolean flag to drop to a restricted user namespace or unprivileged UID.
    public let dropPrivileges: Bool
    /// Target UID if dropPrivileges is set.
    public let targetUid: UInt32
    /// Target GID if dropPrivileges is set.
    public let targetGid: UInt32
    /// Array of syscall names to filter/deny.
    public let deniedSyscalls: [String]

    /// Initializes a new SandboxConfig.
    /// - Parameters:
    ///   - mounts: Array of mounts.
    ///   - disableNetwork: Disable network access.
    ///   - envVars: Array of environment variables.
    ///   - timeoutSecs: Execution timeout.
    ///   - maxMemoryMb: Memory limit.
    ///   - maxCpuPercent: CPU limit.
    ///   - dropPrivileges: Drop privileges flag.
    ///   - targetUid: Target user ID.
    ///   - targetGid: Target group ID.
    ///   - deniedSyscalls: Syscalls to deny.
    public init(
        mounts: [SandboxMount] = [],
        disableNetwork: Bool = false,
        envVars: [String] = [],
        timeoutSecs: UInt32 = 0,
        maxMemoryMb: UInt32 = 0,
        maxCpuPercent: UInt32 = 0,
        dropPrivileges: Bool = false,
        targetUid: UInt32 = 0,
        targetGid: UInt32 = 0,
        deniedSyscalls: [String] = []
    ) {
        self.mounts = mounts
        self.disableNetwork = disableNetwork
        self.envVars = envVars
        self.timeoutSecs = timeoutSecs
        self.maxMemoryMb = maxMemoryMb
        self.maxCpuPercent = maxCpuPercent
        self.dropPrivileges = dropPrivileges
        self.targetUid = targetUid
        self.targetGid = targetGid
        self.deniedSyscalls = deniedSyscalls
    }
}

/// A high-level, safe wrapper around the `libmountsandbox` C API.
public struct LibMountSandbox {
    
    /// Represents errors that can occur during sandbox execution.
    public enum SandboxError: Error {
        /// The specified engine is invalid.
        case invalidEngine(String)
        /// The engine failed to initialize.
        case initializationFailed(String)
    }

    /// Initializes a new LibMountSandbox instance.
    public init() {}

    /// Executes a command inside the specified sandbox engine.
    ///
    /// - Parameters:
    ///   - engineName: The name of the sandbox engine (e.g., "dummy", "native", "docker", "podman", "gvisor").
    ///   - commandArgs: The command and its arguments.
    ///   - config: Optional configuration for the sandbox execution.
    /// - Returns: The exit status of the executed command.
    public func execute(
        engineName: String,
        commandArgs: [String],
        config: SandboxConfig? = nil
    ) throws -> Int32 {
        var enginePtr: UnsafeMutablePointer<sandbox_engine_t>? = nil
        
        let res = engineName.withCString { cEngineName in
            get_sandbox_engine(cEngineName, &enginePtr)
        }
        
        guard res == 0, let engine = enginePtr?.pointee else {
            throw SandboxError.invalidEngine(engineName)
        }
        
        if let initFunc = engine.`init` {
            let initRes = initFunc()
            guard initRes == 0 else {
                throw SandboxError.initializationFailed(engineName)
            }
        }
        
        defer {
            if let cleanupFunc = engine.cleanup {
                cleanupFunc()
            }
        }

        var cConfig = sandbox_config_t()
        
        // We must keep all swift strings alive while C is using their c-string pointers
        var cStrings: [UnsafeMutablePointer<CChar>?] = []
        let retainCString = { (s: String) -> UnsafeMutablePointer<CChar>? in
            // Use strdup so we can control lifetime exactly until the end of the function
            let cstr = strdup(s)
            return cstr
        }
        
        defer {
            for cstr in cStrings {
                if let ptr = cstr {
                    free(UnsafeMutableRawPointer(mutating: ptr))
                }
            }
        }

        var cMounts: [sandbox_mount_t] = []
        var cEnvPtrs: [UnsafePointer<CChar>?] = []
        var cSyscallPtrs: [UnsafePointer<CChar>?] = []

        if let cfg = config {
            if !cfg.mounts.isEmpty {
                for m in cfg.mounts {
                    let ptr = retainCString(m.dir)
                    cStrings.append(ptr)
                    cMounts.append(sandbox_mount_t(dir: UnsafePointer(ptr), read_only: m.readOnly ? 1 : 0))
                }
            }
            
            if !cfg.envVars.isEmpty {
                for env in cfg.envVars {
                    let ptr = retainCString(env)
                    cStrings.append(ptr)
                    cEnvPtrs.append(UnsafePointer(ptr))
                }
            }
            
            if !cfg.deniedSyscalls.isEmpty {
                for sc in cfg.deniedSyscalls {
                    let ptr = retainCString(sc)
                    cStrings.append(ptr)
                    cSyscallPtrs.append(UnsafePointer(ptr))
                }
            }
            
            cConfig.disable_network = cfg.disableNetwork ? 1 : 0
            cConfig.timeout_secs = CUnsignedInt(cfg.timeoutSecs)
            cConfig.max_memory_mb = CUnsignedInt(cfg.maxMemoryMb)
            cConfig.max_cpu_percent = CUnsignedInt(cfg.maxCpuPercent)
            cConfig.drop_privileges = cfg.dropPrivileges ? 1 : 0
            cConfig.target_uid = CUnsignedInt(cfg.targetUid)
            cConfig.target_gid = CUnsignedInt(cfg.targetGid)
        }
        
        var cArgv: [UnsafeMutablePointer<CChar>?] = []
        for arg in commandArgs {
            let ptr = retainCString(arg)
            cStrings.append(ptr)
            cArgv.append(ptr)
        }
        
        return cMounts.withUnsafeBufferPointer { mountsBuf in
            cConfig.mounts = mountsBuf.baseAddress
            cConfig.mount_count = mountsBuf.count
            
            return cEnvPtrs.withUnsafeBufferPointer { envBuf in
                cConfig.env_vars = UnsafeMutablePointer(mutating: envBuf.baseAddress)
                cConfig.env_count = envBuf.count
                
                return cSyscallPtrs.withUnsafeBufferPointer { syscallBuf in
                    cConfig.denied_syscalls = UnsafeMutablePointer(mutating: syscallBuf.baseAddress)
                    cConfig.denied_syscall_count = syscallBuf.count
                    
                    return cArgv.withUnsafeBufferPointer { argvBuf in
                        guard let executeFunc = engine.execute else {
                            return -1
                        }
                        
                        let argvMutable = UnsafeMutablePointer(mutating: argvBuf.baseAddress)
                        return withUnsafePointer(to: &cConfig) { cfgPtr in
                            typealias ExecuteType = @convention(c) (UnsafePointer<sandbox_config_t>?, Int32, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>?) -> Int32
                            let executeAny: Any = executeFunc
                            if let f = executeAny as? ExecuteType {
                                return f(cfgPtr, Int32(commandArgs.count), argvMutable)
                            } else {
                                return executeFunc(cfgPtr, Int32(commandArgs.count), argvMutable)
                            }
                        }
                    }
                }
            }
        }
    }
}
