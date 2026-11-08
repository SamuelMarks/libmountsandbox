//! Rust FFI bindings for `libmountsandbox`.
//!
//! This crate provides safe and unsafe bindings to the `libmountsandbox` C library.

#![deny(missing_docs)]

use libc::{c_char, c_int, c_uint, size_t};
use std::ffi::CString;
use std::ptr;

/// Represents a single directory mount inside the sandbox.
#[repr(C)]
pub struct CSandboxMount {
    /// The directory path on the host to mount.
    pub dir: *const c_char,
    /// Boolean flag (1=true, 0=false) indicating if the mount is read-only.
    pub read_only: c_int,
}

/// Configuration parameters for a sandbox execution.
#[repr(C)]
pub struct CSandboxConfig {
    /// Array of mount points to expose in the sandbox.
    pub mounts: *const CSandboxMount,
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
    /// Maximum CPU limit in percent. 0 means no limit.
    pub max_cpu_percent: c_uint,
    /// Boolean flag to drop to a restricted user namespace.
    pub drop_privileges: c_int,
    /// Target UID if drop_privileges is set.
    pub target_uid: c_uint,
    /// Target GID if drop_privileges is set.
    pub target_gid: c_uint,
    /// Array of syscall names to filter/deny.
    pub denied_syscalls: *const *const c_char,
    /// Number of syscalls in the denied_syscalls array.
    pub denied_syscall_count: size_t,
    /// Optional path to a custom Seccomp BPF profile.
    pub seccomp_profile_path: *const c_char,
    /// Optional name of a custom AppArmor profile.
    pub apparmor_profile: *const c_char,
    /// Boolean flag to allocate a pseudo-terminal (PTY).
    pub use_pty: c_int,
    /// Maximum network bandwidth in Mbps.
    pub max_network_mbps: c_uint,
}

/// Defines the interface for a specific sandbox implementation.
#[repr(C)]
pub struct CSandboxEngine {
    /// Short identifier for the engine.
    pub engine_name: *const c_char,
    /// Human-readable description of the engine.
    pub description: *const c_char,
    /// Initializes the sandbox engine.
    pub init: extern "C" fn() -> c_int,
    /// Executes a command within the sandboxed environment.
    pub execute: extern "C" fn(*const CSandboxConfig, c_int, *mut *mut c_char, *mut c_int) -> c_int,
    /// Executes a command asynchronously.
    pub execute_async: extern "C" fn(
        *const CSandboxConfig,
        c_int,
        *mut *mut c_char,
        *mut *mut libc::c_void,
    ) -> c_int,
    /// Waits for an asynchronous process.
    pub wait_process: extern "C" fn(*mut libc::c_void, *mut c_int) -> c_int,
    /// Frees an asynchronous process handle.
    pub free_process: extern "C" fn(*mut libc::c_void) -> c_int,
    /// Cleans up any resources allocated by the engine.
    pub cleanup: extern "C" fn() -> c_int,
}

extern "C" {
    /// Retrieves a sandbox engine instance by its short name.
    pub fn get_sandbox_engine(name: *const c_char, engine_out: *mut *mut CSandboxEngine) -> c_int;
}

/// Safe Rust representation of a single directory mount.
#[derive(Debug, Clone)]
pub struct SandboxMount {
    /// The directory path on the host to mount.
    pub dir: String,
    /// Boolean flag indicating if the mount is read-only.
    pub read_only: bool,
}

/// Safe Rust representation of the sandbox configuration.
#[derive(Debug, Clone, Default)]
pub struct SandboxConfig {
    /// Array of mount points to expose in the sandbox.
    pub mounts: Vec<SandboxMount>,
    /// Boolean flag to disable network access in the sandbox.
    pub disable_network: bool,
    /// Array of environment variable strings in "KEY=VALUE" format.
    pub env_vars: Vec<String>,
    /// Execution timeout in seconds. A value of 0 means no timeout.
    pub timeout_secs: u32,
    /// Maximum memory limit in Megabytes. 0 means no limit.
    pub max_memory_mb: u32,
    /// Maximum CPU limit in percent. 0 means no limit.
    pub max_cpu_percent: u32,
    /// Boolean flag to drop to a restricted user namespace.
    pub drop_privileges: bool,
    /// Target UID if drop_privileges is set.
    pub target_uid: u32,
    /// Target GID if drop_privileges is set.
    pub target_gid: u32,
    /// Array of syscall names to filter/deny.
    pub denied_syscalls: Vec<String>,
    /// Optional path to a custom Seccomp BPF profile.
    pub seccomp_profile_path: Option<String>,
    /// Optional name of a custom AppArmor profile.
    pub apparmor_profile: Option<String>,
    /// Boolean flag to allocate a pseudo-terminal (PTY).
    pub use_pty: bool,
    /// Maximum network bandwidth in Mbps.
    pub max_network_mbps: u32,
}

/// Main entry point for interacting with `libmountsandbox`.
#[derive(Default)]
pub struct LibMountSandbox;

impl LibMountSandbox {
    /// Creates a new `LibMountSandbox` instance.
    pub fn new() -> Self {
        Self
    }

    /// Executes a command inside the specified sandbox engine.
    pub fn execute(
        &self,
        engine_name: &str,
        command_args: &[&str],
        config: Option<&SandboxConfig>,
    ) -> Result<i32, String> {
        let c_engine_name = CString::new(engine_name).map_err(|e| e.to_string())?;
        let mut engine_ptr: *mut CSandboxEngine = ptr::null_mut();
        let rc = unsafe { get_sandbox_engine(c_engine_name.as_ptr(), &mut engine_ptr) };
        if rc != 0 || engine_ptr.is_null() {
            return Err(format!("Engine '{}' not found.", engine_name));
        }

        let engine = unsafe { &*engine_ptr };
        if (engine.init)() != 0 {
            return Err(format!("Failed to initialize engine '{}'.", engine_name));
        }

        let mut c_mounts = Vec::new();
        let mut c_mount_dirs = Vec::new();
        let mut c_env_vars = Vec::new();
        let mut c_env_var_ptrs = Vec::new();
        let mut c_denied_syscalls = Vec::new();
        let mut c_denied_syscall_ptrs = Vec::new();

        let default_config = SandboxConfig::default();
        let cfg = config.unwrap_or(&default_config);

        for m in &cfg.mounts {
            let c_dir = CString::new(m.dir.as_str()).map_err(|e| e.to_string())?;
            c_mounts.push(CSandboxMount {
                dir: c_dir.as_ptr(),
                read_only: if m.read_only { 1 } else { 0 },
            });
            c_mount_dirs.push(c_dir);
        }

        for env in &cfg.env_vars {
            let c_env = CString::new(env.as_str()).map_err(|e| e.to_string())?;
            c_env_var_ptrs.push(c_env.as_ptr());
            c_env_vars.push(c_env);
        }

        for sys in &cfg.denied_syscalls {
            let c_sys = CString::new(sys.as_str()).map_err(|e| e.to_string())?;
            c_denied_syscall_ptrs.push(c_sys.as_ptr());
            c_denied_syscalls.push(c_sys);
        }

        let c_seccomp = match &cfg.seccomp_profile_path {
            Some(s) => Some(CString::new(s.as_str()).map_err(|e| e.to_string())?),
            None => None,
        };
        let c_apparmor = match &cfg.apparmor_profile {
            Some(s) => Some(CString::new(s.as_str()).map_err(|e| e.to_string())?),
            None => None,
        };

        let c_config = CSandboxConfig {
            mounts: if c_mounts.is_empty() {
                ptr::null()
            } else {
                c_mounts.as_ptr()
            },
            mount_count: c_mounts.len(),
            disable_network: if cfg.disable_network { 1 } else { 0 },
            env_vars: if c_env_var_ptrs.is_empty() {
                ptr::null()
            } else {
                c_env_var_ptrs.as_ptr()
            },
            env_count: c_env_var_ptrs.len(),
            timeout_secs: cfg.timeout_secs,
            stdout_buffer: ptr::null_mut(),
            stdout_size: ptr::null_mut(),
            stderr_buffer: ptr::null_mut(),
            stderr_size: ptr::null_mut(),
            max_memory_mb: cfg.max_memory_mb,
            max_cpu_percent: cfg.max_cpu_percent,
            drop_privileges: if cfg.drop_privileges { 1 } else { 0 },
            target_uid: cfg.target_uid,
            target_gid: cfg.target_gid,
            denied_syscalls: if c_denied_syscall_ptrs.is_empty() {
                ptr::null()
            } else {
                c_denied_syscall_ptrs.as_ptr()
            },
            denied_syscall_count: c_denied_syscall_ptrs.len(),
            seccomp_profile_path: c_seccomp.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            apparmor_profile: c_apparmor.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
            use_pty: if cfg.use_pty { 1 } else { 0 },
            max_network_mbps: cfg.max_network_mbps,
        };

        let mut c_args = Vec::new();
        let mut c_arg_ptrs = Vec::new();
        for arg in command_args {
            let c_arg = CString::new(*arg).map_err(|e| e.to_string())?;
            c_arg_ptrs.push(c_arg.as_ptr() as *mut c_char);
            c_args.push(c_arg);
        }
        c_arg_ptrs.push(ptr::null_mut());

        let mut status: c_int = 0;
        let exec_rc = (engine.execute)(
            &c_config,
            command_args.len() as c_int,
            c_arg_ptrs.as_mut_ptr(),
            &mut status,
        );
        let cleanup_rc = (engine.cleanup)();

        if exec_rc != 0 || cleanup_rc != 0 {
            return Ok(-1);
        }
        Ok(status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dummy_engine() {
        let sandbox = LibMountSandbox::new();
        let status = sandbox
            .execute("dummy", &["echo", "hello"], None)
            .expect("Execution failed");
        assert_eq!(status, 0);
    }

    #[test]
    fn test_invalid_engine() {
        let sandbox = LibMountSandbox::new();
        let res = sandbox.execute("nonexistent", &["ls"], None);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "Engine 'nonexistent' not found.");
    }

    #[test]
    fn test_full_config() {
        let sandbox = LibMountSandbox::new();
        let config = SandboxConfig {
            mounts: vec![
                SandboxMount {
                    dir: "/tmp".to_string(),
                    read_only: false,
                },
                SandboxMount {
                    dir: "/var".to_string(),
                    read_only: true,
                },
            ],
            disable_network: true,
            env_vars: vec!["KEY=VAL".to_string()],
            timeout_secs: 5,
            max_memory_mb: 128,
            max_cpu_percent: 50,
            drop_privileges: true,
            target_uid: 1000,
            target_gid: 1000,
            denied_syscalls: vec!["ptrace".to_string()],
            seccomp_profile_path: None,
            apparmor_profile: None,
            use_pty: false,
            max_network_mbps: 0,
        };
        let status = sandbox
            .execute("dummy", &["test"], Some(&config))
            .expect("Execution failed");
        assert_eq!(status, 0);
    }

    #[test]
    fn test_execute_with_null_byte_in_engine_name() {
        let sandbox = LibMountSandbox::new();
        let result = sandbox.execute("dummy\0engine", &["test"], None);
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
