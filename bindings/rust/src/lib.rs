//! Rust FFI bindings for `libmountsandbox`.
//!
//! This crate provides safe and unsafe bindings to the `libmountsandbox` C library.

#![deny(missing_docs)]

use libc::{c_char, c_int, c_uint, size_t};
use std::ffi::CString;
use std::ptr;

/// Represents a single directory mount inside the sandbox.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SandboxMount {
    /// The directory path on the host to mount.
    pub dir: *const c_char,
    /// Boolean flag (1=true, 0=false) indicating if the mount is read-only.
    pub read_only: c_int,
}

/// Configuration parameters for a sandbox execution.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Array of mount points to expose in the sandbox.
    pub mounts: *const SandboxMount,
    /// Number of mounts in the mounts array.
    pub mount_count: size_t,
    /// Boolean flag (1=true, 0=false) to disable network access in the sandbox.
    pub disable_network: c_int,
    /// Array of environment variable strings in "KEY=VALUE" format.
    pub env_vars: *const *const c_char,
    /// Number of environment variables in env_vars.
    pub env_count: size_t,
    /// Execution timeout in seconds. A value of 0 means no timeout.
    pub timeout_secs: c_uint,
    /// Optional pointer to a buffer that will be allocated and filled with stdout.
    pub stdout_buffer: *mut *mut c_char,
    /// Optional pointer to a size_t that will contain the length of stdout_buffer.
    pub stdout_size: *mut size_t,
    /// Optional pointer to a buffer that will be allocated and filled with stderr.
    pub stderr_buffer: *mut *mut c_char,
    /// Optional pointer to a size_t that will contain the length of stderr_buffer.
    pub stderr_size: *mut size_t,
    /// Maximum memory limit in Megabytes. 0 means no limit.
    pub max_memory_mb: c_uint,
    /// Maximum CPU limit in percent (e.g., 100 = 1 full core). 0 means no limit.
    pub max_cpu_percent: c_uint,
    /// Boolean flag (1=true, 0=false) to drop to a restricted user namespace or unprivileged UID.
    pub drop_privileges: c_int,
    /// Target UID if drop_privileges is set.
    pub target_uid: c_uint,
    /// Target GID if drop_privileges is set.
    pub target_gid: c_uint,
    /// Array of syscall names to filter/deny.
    pub denied_syscalls: *const *const c_char,
    /// Number of syscalls in the denied_syscalls array.
    pub denied_syscall_count: size_t,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        SandboxConfig {
            mounts: ptr::null(),
            mount_count: 0,
            disable_network: 0,
            env_vars: ptr::null(),
            env_count: 0,
            timeout_secs: 0,
            stdout_buffer: ptr::null_mut(),
            stdout_size: ptr::null_mut(),
            stderr_buffer: ptr::null_mut(),
            stderr_size: ptr::null_mut(),
            max_memory_mb: 0,
            max_cpu_percent: 0,
            drop_privileges: 0,
            target_uid: 0,
            target_gid: 0,
            denied_syscalls: ptr::null(),
            denied_syscall_count: 0,
        }
    }
}

/// Defines the interface for a specific sandbox implementation.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SandboxEngine {
    /// Short identifier for the engine (e.g., "docker", "podman", "gvisor", "native").
    pub engine_name: *const c_char,
    /// Human-readable description of the engine.
    pub description: *const c_char,
    /// Initializes the sandbox engine.
    pub init: Option<extern "C" fn() -> c_int>,
    /// Executes a command within the sandboxed environment.
    pub execute: Option<
        extern "C" fn(
            config: *const SandboxConfig,
            argc: c_int,
            argv: *const *const c_char,
        ) -> c_int,
    >,
    /// Cleans up any resources allocated by the engine.
    pub cleanup: Option<extern "C" fn()>,
}

unsafe extern "C" {
    /// Retrieves a sandbox engine instance by its short name.
    pub fn get_sandbox_engine(name: *const c_char, engine_out: *mut *mut SandboxEngine) -> c_int;
}

/// A high-level, safe wrapper around the `libmountsandbox` C API.
pub struct LibMountSandbox {
    _dummy: (), // Prevent direct instantiation if needed
}

/// Configuration options for executing a command in the sandbox.
#[derive(Debug, Clone, Default)]
pub struct ExecuteConfig {
    /// Mounts to expose inside the sandbox.
    pub mounts: Vec<(String, bool)>,
    /// Whether network should be disabled.
    pub disable_network: bool,
    /// Environment variables to set.
    pub env_vars: Vec<String>,
    /// Timeout in seconds.
    pub timeout_secs: u32,
    /// Maximum memory in MB.
    pub max_memory_mb: u32,
    /// Maximum CPU percentage.
    pub max_cpu_percent: u32,
    /// Whether to drop privileges.
    pub drop_privileges: bool,
    /// Target UID for dropped privileges.
    pub target_uid: u32,
    /// Target GID for dropped privileges.
    pub target_gid: u32,
    /// Denied syscalls.
    pub denied_syscalls: Vec<String>,
}

impl LibMountSandbox {
    /// Creates a new instance of `LibMountSandbox`.
    pub fn new() -> Self {
        LibMountSandbox { _dummy: () }
    }

    /// Executes a command inside the specified sandbox engine.
    ///
    /// # Arguments
    ///
    /// * `engine_name` - The name of the sandbox engine (e.g., "dummy", "native", "docker").
    /// * `command_args` - The command and its arguments.
    /// * `config` - Optional configuration for the sandbox execution.
    ///
    /// # Returns
    ///
    /// The exit status of the executed command, or an error if initialization fails.
    pub fn execute(
        &self,
        engine_name: &str,
        command_args: &[&str],
        config: Option<&ExecuteConfig>,
    ) -> Result<i32, String> {
        let engine_name_c = CString::new(engine_name).map_err(|e| e.to_string())?;

        let mut engine_ptr: *mut SandboxEngine = std::ptr::null_mut();
        let res = unsafe { get_sandbox_engine(engine_name_c.as_ptr(), &mut engine_ptr) };
        if res != 0 || engine_ptr.is_null() {
            return Err(format!("Unknown sandbox engine: {}", engine_name));
        }

        let engine = unsafe { &*engine_ptr };

        if let Some(init) = engine.init {
            let res = init();
            if res != 0 {
                return Err(format!("Failed to initialize engine: {}", engine_name));
            }
        }

        let mut c_config = SandboxConfig::default();

        let mut _c_mount_dirs: Vec<CString> = Vec::new();
        let mut c_mounts: Vec<SandboxMount> = Vec::new();

        let mut _c_envs: Vec<CString> = Vec::new();
        let mut c_env_ptrs: Vec<*const c_char> = Vec::new();

        let mut _c_syscalls: Vec<CString> = Vec::new();
        let mut c_syscall_ptrs: Vec<*const c_char> = Vec::new();

        if let Some(cfg) = config {
            if !cfg.mounts.is_empty() {
                for (dir, ro) in &cfg.mounts {
                    let c_dir = CString::new(dir.as_str()).map_err(|e| e.to_string())?;
                    let c_mount = SandboxMount {
                        dir: c_dir.as_ptr(),
                        read_only: if *ro { 1 } else { 0 },
                    };
                    _c_mount_dirs.push(c_dir);
                    c_mounts.push(c_mount);
                }
                c_config.mounts = c_mounts.as_ptr();
                c_config.mount_count = c_mounts.len() as size_t;
            }

            c_config.disable_network = if cfg.disable_network { 1 } else { 0 };

            if !cfg.env_vars.is_empty() {
                for env in &cfg.env_vars {
                    let c_env = CString::new(env.as_str()).map_err(|e| e.to_string())?;
                    c_env_ptrs.push(c_env.as_ptr());
                    _c_envs.push(c_env);
                }
                c_config.env_vars = c_env_ptrs.as_ptr();
                c_config.env_count = c_env_ptrs.len() as size_t;
            }

            c_config.timeout_secs = cfg.timeout_secs;
            c_config.max_memory_mb = cfg.max_memory_mb;
            c_config.max_cpu_percent = cfg.max_cpu_percent;

            c_config.drop_privileges = if cfg.drop_privileges { 1 } else { 0 };
            c_config.target_uid = cfg.target_uid;
            c_config.target_gid = cfg.target_gid;

            if !cfg.denied_syscalls.is_empty() {
                for sc in &cfg.denied_syscalls {
                    let c_sc = CString::new(sc.as_str()).map_err(|e| e.to_string())?;
                    c_syscall_ptrs.push(c_sc.as_ptr());
                    _c_syscalls.push(c_sc);
                }
                c_config.denied_syscalls = c_syscall_ptrs.as_ptr();
                c_config.denied_syscall_count = c_syscall_ptrs.len() as size_t;
            }
        }

        let mut _c_args: Vec<CString> = Vec::new();
        let mut c_arg_ptrs: Vec<*const c_char> = Vec::new();

        for arg in command_args {
            let c_arg = CString::new(*arg).map_err(|e| e.to_string())?;
            c_arg_ptrs.push(c_arg.as_ptr());
            _c_args.push(c_arg);
        }
        // Null-terminate the argument array if the C API expects it, though argc is passed.
        // It's safer to just provide what is needed.
        // The execute function takes (const sandbox_config_t *config, int argc, char **argv)
        let argc = c_arg_ptrs.len() as c_int;

        let status = if let Some(execute) = engine.execute {
            execute(&c_config, argc, c_arg_ptrs.as_ptr())
        } else {
            -1
        };

        if let Some(cleanup) = engine.cleanup {
            cleanup();
        }

        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execute_dummy_engine() {
        let sandbox = LibMountSandbox::new();
        let args = vec!["echo", "hello rust"];
        let status = sandbox.execute("dummy", &args, None).unwrap();
        // The dummy engine always returns 0.
        assert_eq!(status, 0);
    }

    #[test]
    fn test_execute_unknown_engine() {
        let sandbox = LibMountSandbox::new();
        let args = vec!["echo", "hello"];
        let result = sandbox.execute("unknown_engine_test", &args, None);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Unknown sandbox engine: unknown_engine_test"
        );
    }

    #[test]
    fn test_execute_with_config() {
        let sandbox = LibMountSandbox::new();
        let args = vec!["test"];
        let config = ExecuteConfig {
            mounts: vec![("/tmp".to_string(), true)],
            disable_network: true,
            env_vars: vec!["TEST=1".to_string()],
            timeout_secs: 10,
            max_memory_mb: 512,
            max_cpu_percent: 50,
            drop_privileges: true,
            target_uid: 1000,
            target_gid: 1000,
            denied_syscalls: vec!["ptrace".to_string()],
        };

        let status = sandbox.execute("dummy", &args, Some(&config)).unwrap();
        assert_eq!(status, 0);
    }

    #[test]
    fn test_execute_with_null_byte_in_engine_name() {
        let sandbox = LibMountSandbox::new();
        let args = vec!["test"];
        let result = sandbox.execute("dummy\0engine", &args, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("nul byte found in provided data"));
    }

    #[test]
    fn test_execute_with_null_byte_in_args() {
        let sandbox = LibMountSandbox::new();
        let args = vec!["test\0null"];
        let result = sandbox.execute("dummy", &args, None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("nul byte found in provided data"));
    }
}
