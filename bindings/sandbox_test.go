package sandbox

import (
        "path/filepath"
        "runtime"
        "testing"
)

func getLibPath() string {
        libName := "libmountsandbox.so"
        if runtime.GOOS == "darwin" {
                libName = "libmountsandbox.dylib"
        } else if runtime.GOOS == "windows" {
                libName = "mountsandbox.dll"
        }
        return filepath.Join("..", "build", libName)
}

func TestLibMountSandbox_Execute(t *testing.T) {
        // The dummy engine just returns 0 when initialized and executed successfully
        sandbox := NewLibMountSandbox(getLibPath())

        config := &SandboxConfig{
                Mounts: []SandboxMount{
                        {Dir: "/tmp", ReadOnly: false},
                        {Dir: "/etc", ReadOnly: true},
                },
                DisableNetwork: true,
                EnvVars: []string{
                        "TEST=1",
                        "FOO=bar",
                },
                TimeoutSecs:    5,
                MaxMemoryMb:    128,
                MaxCpuPercent:  100,
                DropPrivileges: true,
                TargetUid:      1000,
                TargetGid:      1000,
                DeniedSyscalls: []string{
                        "ptrace",
                },
        }

        status, err := sandbox.Execute("dummy", []string{"ls", "-la"}, config)
        if err != nil {
                t.Fatalf("expected no error, got %v", err)
        }

        if status != 0 {
                t.Errorf("expected status 0, got %d", status)
        }
}

func TestLibMountSandbox_Execute_UnknownEngine(t *testing.T) {
        sandbox := NewLibMountSandbox(getLibPath())
        _, err := sandbox.Execute("nonexistent_engine", []string{"ls"}, nil)
        if err == nil {
                t.Fatalf("expected error for unknown engine, got nil")
        }
}

func TestLibMountSandbox_Execute_NilConfig(t *testing.T) {
        sandbox := NewLibMountSandbox(getLibPath())
        status, err := sandbox.Execute("dummy", []string{"echo", "hello"}, nil)
        if err != nil {
                t.Fatalf("expected no error, got %v", err)
        }
        if status != 0 {
                t.Errorf("expected status 0, got %d", status)
        }
}
