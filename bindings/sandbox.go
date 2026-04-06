package sandbox

/*
#cgo CFLAGS: -I../src
#cgo LDFLAGS: -L../build -lmountsandbox
#include "sandbox.h"
#include <stdlib.h>

static int call_init(sandbox_engine_t* engine) {
    return engine->init();
}

static int call_execute(sandbox_engine_t* engine, const sandbox_config_t *config, int argc, char **argv) {
    return engine->execute(config, argc, argv);
}

static void call_cleanup(sandbox_engine_t* engine) {
    engine->cleanup();
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// SandboxMount represents a single directory mount inside the sandbox.
type SandboxMount struct {
	// Dir is the directory path on the host to mount.
	Dir string
	// ReadOnly indicates if the mount is read-only.
	ReadOnly bool
}

// SandboxConfig holds configuration parameters for a sandbox execution.
type SandboxConfig struct {
	// Mounts is the array of mount points to expose.
	Mounts []SandboxMount
	// DisableNetwork disables network access if true.
	DisableNetwork bool
	// EnvVars is a list of environment variables in "KEY=VALUE" format.
	EnvVars []string
	// TimeoutSecs is the execution timeout in seconds.
	TimeoutSecs uint
	// MaxMemoryMb is the maximum memory limit in Megabytes.
	MaxMemoryMb uint
	// MaxCpuPercent is the maximum CPU limit in percent.
	MaxCpuPercent uint
	// DropPrivileges indicates whether to drop to a restricted user namespace.
	DropPrivileges bool
	// TargetUid is the target UID if DropPrivileges is set.
	TargetUid uint
	// TargetGid is the target GID if DropPrivileges is set.
	TargetGid uint
	// DeniedSyscalls is an array of syscall names to filter/deny.
	DeniedSyscalls []string
}

// LibMountSandbox is the Go wrapper for the C libmountsandbox.
type LibMountSandbox struct {
	// LibPath is the path to the shared library (kept for API compatibility).
	LibPath string
}

// NewLibMountSandbox creates a new instance of LibMountSandbox.
// Note: In Go, linking is typically done at build time via cgo LDFLAGS.
// The libPath parameter is kept for compatibility with other FFI bindings.
func NewLibMountSandbox(libPath string) *LibMountSandbox {
	return &LibMountSandbox{LibPath: libPath}
}

// Execute runs a command within the specified sandbox engine.
// Returns the exit status of the executed command, or an error if initialization fails.
func (l *LibMountSandbox) Execute(engineName string, commandArgs []string, config *SandboxConfig) (int, error) {
	cEngineName := C.CString(engineName)
	defer C.free(unsafe.Pointer(cEngineName))

	var enginePtr *C.sandbox_engine_t
        res := C.get_sandbox_engine(cEngineName, &enginePtr)
        if res != 0 || enginePtr == nil {
                return -1, fmt.Errorf("unknown sandbox engine: %s", engineName)
        }
	

	if C.call_init(enginePtr) != 0 {
		return -1, fmt.Errorf("failed to initialize engine: %s", engineName)
	}
	defer C.call_cleanup(enginePtr)

	var cConfig C.sandbox_config_t
	// C.sandbox_config_t is 0-initialized automatically in Go

	if config != nil {
		if len(config.Mounts) > 0 {
			numMounts := len(config.Mounts)
			cMountsPtr := (*C.sandbox_mount_t)(C.malloc(C.size_t(numMounts) * C.size_t(unsafe.Sizeof(C.sandbox_mount_t{}))))
			cMountsSlice := unsafe.Slice(cMountsPtr, numMounts)
			for i, m := range config.Mounts {
				cMountsSlice[i].dir = C.CString(m.Dir)
				if m.ReadOnly {
					cMountsSlice[i].read_only = 1
				} else {
					cMountsSlice[i].read_only = 0
				}
			}
			cConfig.mounts = cMountsPtr
			cConfig.mount_count = C.size_t(numMounts)
			defer func() {
				for i := 0; i < numMounts; i++ {
					C.free(unsafe.Pointer(cMountsSlice[i].dir))
				}
				C.free(unsafe.Pointer(cMountsPtr))
			}()
		}

		if config.DisableNetwork {
			cConfig.disable_network = 1
		}

		if len(config.EnvVars) > 0 {
			numEnvs := len(config.EnvVars)
			cEnvsPtr := (**C.char)(C.malloc(C.size_t(numEnvs) * C.size_t(unsafe.Sizeof((*C.char)(nil)))))
			cEnvsSlice := unsafe.Slice(cEnvsPtr, numEnvs)
			for i, env := range config.EnvVars {
				cEnvsSlice[i] = C.CString(env)
			}
			cConfig.env_vars = cEnvsPtr
			cConfig.env_count = C.size_t(numEnvs)
			defer func() {
				for i := 0; i < numEnvs; i++ {
					C.free(unsafe.Pointer(cEnvsSlice[i]))
				}
				C.free(unsafe.Pointer(cEnvsPtr))
			}()
		}

		cConfig.timeout_secs = C.uint(config.TimeoutSecs)
		cConfig.max_memory_mb = C.uint(config.MaxMemoryMb)
		cConfig.max_cpu_percent = C.uint(config.MaxCpuPercent)

		if config.DropPrivileges {
			cConfig.drop_privileges = 1
		}
		cConfig.target_uid = C.uint(config.TargetUid)
		cConfig.target_gid = C.uint(config.TargetGid)

		if len(config.DeniedSyscalls) > 0 {
			numSyscalls := len(config.DeniedSyscalls)
			cSyscallsPtr := (**C.char)(C.malloc(C.size_t(numSyscalls) * C.size_t(unsafe.Sizeof((*C.char)(nil)))))
			cSyscallsSlice := unsafe.Slice(cSyscallsPtr, numSyscalls)
			for i, sc := range config.DeniedSyscalls {
				cSyscallsSlice[i] = C.CString(sc)
			}
			cConfig.denied_syscalls = cSyscallsPtr
			cConfig.denied_syscall_count = C.size_t(numSyscalls)
			defer func() {
				for i := 0; i < numSyscalls; i++ {
					C.free(unsafe.Pointer(cSyscallsSlice[i]))
				}
				C.free(unsafe.Pointer(cSyscallsPtr))
			}()
		}
	}

	cArgc := C.int(len(commandArgs))
	cArgvPtr := (**C.char)(C.malloc(C.size_t(len(commandArgs)+1) * C.size_t(unsafe.Sizeof((*C.char)(nil)))))
	cArgvSlice := unsafe.Slice(cArgvPtr, len(commandArgs)+1)
	for i, arg := range commandArgs {
		cArgvSlice[i] = C.CString(arg)
	}
	cArgvSlice[len(commandArgs)] = nil
	defer func() {
		for i := 0; i < len(commandArgs); i++ {
			C.free(unsafe.Pointer(cArgvSlice[i]))
		}
		C.free(unsafe.Pointer(cArgvPtr))
	}()

	status := C.call_execute(enginePtr, &cConfig, cArgc, cArgvPtr)
	return int(status), nil
}
