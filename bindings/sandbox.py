from ctypes import (
    CDLL,
    Structure,
    c_char_p,
    c_int,
    c_uint,
    c_size_t,
    c_void_p,
    POINTER,
    byref,
    string_at,
)


class SandboxMount(Structure):
    _fields_ = [("dir", c_char_p), ("read_only", c_int)]


class SandboxConfig(Structure):
    _fields_ = [
        ("mounts", POINTER(SandboxMount)),
        ("mount_count", c_size_t),
        ("disable_network", c_int),
        ("env_vars", POINTER(c_char_p)),
        ("env_count", c_size_t),
        ("timeout_secs", c_uint),
        ("stdout_buffer", POINTER(c_char_p)),
        ("stdout_size", POINTER(c_size_t)),
        ("stderr_buffer", POINTER(c_char_p)),
        ("stderr_size", POINTER(c_size_t)),
        ("max_memory_mb", c_uint),
        ("max_cpu_percent", c_uint),
        ("drop_privileges", c_int),
        ("target_uid", c_uint),
        ("target_gid", c_uint),
        ("denied_syscalls", POINTER(c_char_p)),
        ("denied_syscall_count", c_size_t),
        ("seccomp_profile_path", c_char_p),
        ("apparmor_profile", c_char_p),
        ("use_pty", c_int),
        ("max_network_mbps", c_uint),
    ]


class SandboxEngine(Structure):
    _fields_ = [
        ("engine_name", c_char_p),
        ("description", c_char_p),
        ("init", c_void_p),
        ("execute", c_void_p),
        ("execute_async", c_void_p),
        ("wait_process", c_void_p),
        ("free_process", c_void_p),
        ("cleanup", c_void_p),
    ]


class LibMountSandbox:
    def __init__(self, lib_path="./libmountsandbox.so"):
        self.lib = CDLL(lib_path)
        self.lib.get_sandbox_engine.argtypes = [
            c_char_p,
            POINTER(POINTER(SandboxEngine)),
        ]
        self.lib.get_sandbox_engine.restype = c_int

    def execute(
        self, engine_name: str, command_args: list[str], config: SandboxConfig = None
    ) -> int:
        from ctypes import CFUNCTYPE

        engine_ptr = POINTER(SandboxEngine)()
        rc = self.lib.get_sandbox_engine(engine_name.encode("utf-8"), byref(engine_ptr))
        if rc != 0 or not engine_ptr:
            raise ValueError(f"Engine '{engine_name}' not found.")

        engine = engine_ptr.contents

        INIT_FUNC = CFUNCTYPE(c_int)
        EXECUTE_FUNC = CFUNCTYPE(
            c_int, POINTER(SandboxConfig), c_int, POINTER(c_char_p), POINTER(c_int)
        )
        CLEANUP_FUNC = CFUNCTYPE(c_int)

        init_func = INIT_FUNC(engine.init)
        execute_func = EXECUTE_FUNC(engine.execute)
        cleanup_func = CLEANUP_FUNC(engine.cleanup)

        if init_func() != 0:
            raise RuntimeError(f"Failed to initialize engine '{engine_name}'.")

        argc = len(command_args)
        argv = (c_char_p * (argc + 1))()
        for i, arg in enumerate(command_args):
            argv[i] = arg.encode("utf-8")
        argv[argc] = None

        if config is None:
            config = SandboxConfig()
            config.mount_count = 0
            config.env_count = 0
            config.disable_network = 0

        exit_status = c_int(0)
        exec_rc = execute_func(byref(config), argc, argv, byref(exit_status))
        cleanup_func()

        if exec_rc != 0:
            return -1
        return exit_status.value
