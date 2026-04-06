package mountsandbox

import com.sun.jna.Callback
import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.Structure
import com.sun.jna.ptr.PointerByReference
import java.nio.file.Paths

/**
 * Represents a single directory mount inside the sandbox.
 */
open class SandboxMount : Structure() {
    /** The directory path on the host to mount. */
    @JvmField var dir: String? = null
    /** Boolean flag (1=true, 0=false) indicating if the mount is read-only. */
    @JvmField var read_only: Int = 0

    override fun getFieldOrder(): List<String> = listOf("dir", "read_only")
}

/**
 * Configuration parameters for a sandbox execution.
 */
open class SandboxConfig : Structure() {
    /** Array of mount points to expose in the sandbox. */
    @JvmField var mounts: Pointer? = null
    /** Number of mounts in the mounts array. */
    @JvmField var mount_count: Long = 0
    /** Boolean flag (1=true, 0=false) to disable network access. */
    @JvmField var disable_network: Int = 0
    /** Array of environment variable strings in "KEY=VALUE" format. */
    @JvmField var env_vars: Pointer? = null
    /** Number of environment variables. */
    @JvmField var env_count: Long = 0
    /** Execution timeout in seconds. 0 means no timeout. */
    @JvmField var timeout_secs: Int = 0
    /** Optional pointer to a buffer for stdout. */
    @JvmField var stdout_buffer: Pointer? = null
    /** Optional pointer to stdout length. */
    @JvmField var stdout_size: Pointer? = null
    /** Optional pointer to a buffer for stderr. */
    @JvmField var stderr_buffer: Pointer? = null
    /** Optional pointer to stderr length. */
    @JvmField var stderr_size: Pointer? = null
    /** Maximum memory limit in Megabytes. 0 means no limit. */
    @JvmField var max_memory_mb: Int = 0
    /** Maximum CPU limit in percent. 0 means no limit. */
    @JvmField var max_cpu_percent: Int = 0
    /** Boolean flag to drop to restricted user namespace. */
    @JvmField var drop_privileges: Int = 0
    /** Target UID if drop_privileges is set. */
    @JvmField var target_uid: Int = 0
    /** Target GID if drop_privileges is set. */
    @JvmField var target_gid: Int = 0
    /** Array of syscall names to filter/deny. */
    @JvmField var denied_syscalls: Pointer? = null
    /** Number of syscalls in denied_syscalls. */
    @JvmField var denied_syscall_count: Long = 0
    /** Optional path to a custom Seccomp BPF profile (JSON for Docker, BPF for Native). */
    @JvmField var seccomp_profile_path: String? = null
    /** Optional name of a custom AppArmor profile. */
    @JvmField var apparmor_profile: String? = null
    /** Boolean flag (1=true, 0=false) to allocate a pseudo-terminal (PTY) for the sandbox. */
    @JvmField var use_pty: Int = 0
    /** Maximum network bandwidth in Mbps. 0 means unlimited. */
    @JvmField var max_network_mbps: Int = 0

    override fun getFieldOrder(): List<String> = listOf(
        "mounts", "mount_count", "disable_network", "env_vars", "env_count",
        "timeout_secs", "stdout_buffer", "stdout_size", "stderr_buffer", "stderr_size",
        "max_memory_mb", "max_cpu_percent", "drop_privileges", "target_uid", "target_gid",
        "denied_syscalls", "denied_syscall_count",
        "seccomp_profile_path", "apparmor_profile", "use_pty", "max_network_mbps"
    )
}

/** Callback interface for engine initialization. */
interface InitCallback : Callback {
    /** Invokes the initialization function. Returns 0 on success. */
    fun invoke(): Int
}

/** Callback interface for engine execution. */
interface ExecuteCallback : Callback {
    /** Invokes the execution function. Returns the process status code. */
    fun invoke(config: SandboxConfig?, argc: Int, argv: Pointer?): Int
}

/** Callback interface for engine cleanup. */
interface CleanupCallback : Callback {
    /** Invokes the cleanup function. */
    fun invoke()
}

/**
 * Defines the interface for a specific sandbox implementation.
 */
open class SandboxEngine : Structure {
    /** Default constructor. */
    constructor() : super()
    /** Constructor from memory pointer. */
    constructor(p: Pointer) : super(p)

    /** Short identifier for the engine. */
    @JvmField var engine_name: String? = null
    /** Human-readable description. */
    @JvmField var description: String? = null
    /** Function pointer to initialization logic. */
    @JvmField var init: InitCallback? = null
    /** Function pointer to execution logic. */
    @JvmField var execute: ExecuteCallback? = null
    /** Function pointer to cleanup logic. */
    @JvmField var cleanup: CleanupCallback? = null

    override fun getFieldOrder(): List<String> = listOf("engine_name", "description", "init", "execute", "cleanup")
}

/** Native JNA wrapper for libmountsandbox. */
interface LibMountSandbox : Library {
    /**
     * Retrieves a sandbox engine instance by its short name.
     * @param name The string name of the engine to retrieve.
     * @param engine_out Reference pointer to store the engine structure.
     * @return 0 on success.
     */
    fun get_sandbox_engine(name: String, engine_out: PointerByReference): Int
}

/**
 * Wrapper class to interact safely with the Sandbox library.
 * @param libPath Optional custom path to the native library.
 */
class Sandbox(libPath: String? = null) {
    private val lib: LibMountSandbox

    init {
        val path = libPath ?: findLibrary()
        lib = Native.load(path, LibMountSandbox::class.java)
    }

    private fun findLibrary(): String {
        var current = Paths.get("").toAbsolutePath()
        while (current != null) {
            val buildDir = current.resolve("build")
            val so = buildDir.resolve("libmountsandbox.so")
            val dylib = buildDir.resolve("libmountsandbox.dylib")
            val dll = buildDir.resolve("libmountsandbox.dll")

            if (so.toFile().exists()) return so.toString()
            if (dylib.toFile().exists()) return dylib.toString()
            if (dll.toFile().exists()) return dll.toString()
            
            val buildReleaseDir = current.resolve("build/Release")
            val dllRel = buildReleaseDir.resolve("libmountsandbox.dll")
            if (dllRel.toFile().exists()) return dllRel.toString()

            val parent = current.parent
            if (parent == current) break
            current = parent
        }
        return "mountsandbox"
    }

    /**
     * Executes a command within the sandboxed environment.
     * @param engineName Name of the engine to use (e.g. "dummy", "native", "docker", "podman", "gvisor").
     * @param commandArgs The command to execute along with arguments.
     * @param config Optional configuration parameters.
     * @return Execution status code.
     */
    fun execute(engineName: String, commandArgs: List<String>, config: SandboxConfig? = null): Int {
        val engineOut = PointerByReference()
        val res = lib.get_sandbox_engine(engineName, engineOut)
        if (res != 0 || engineOut.value == null) {
            throw IllegalArgumentException("Unknown sandbox engine: $engineName")
        }

        val pointer = engineOut.value
        val engine = SandboxEngine(pointer)
        engine.read()

        val initFunc = engine.init ?: throw IllegalStateException("Engine missing init")
        val executeFunc = engine.execute ?: throw IllegalStateException("Engine missing execute")
        val cleanupFunc = engine.cleanup ?: throw IllegalStateException("Engine missing cleanup")

        if (initFunc.invoke() != 0) {
            throw RuntimeException("Failed to initialize engine: $engineName")
        }

        val argc = commandArgs.size
        val argv = com.sun.jna.StringArray(commandArgs.toTypedArray())

        val cfg = config ?: SandboxConfig()
        
        val status = executeFunc.invoke(cfg, argc, argv)
        cleanupFunc.invoke()

        return status
    }
}
