require 'ffi'

# The LibMountSandbox module provides a Ruby FFI wrapper around the C libmountsandbox library.
module LibMountSandbox
  extend FFI::Library

  # Helper method to dynamically resolve the shared library path based on OS
  def self.resolve_lib_path(custom_path = nil)
    return custom_path if custom_path

    lib_name = case RbConfig::CONFIG['host_os']
               when /darwin/ then 'libmountsandbox.dylib'
               when /mswin|msys|mingw|cygwin|bccwin|wince|emc/ then 'mountsandbox.dll'
               else 'libmountsandbox.so'
               end

    default_path = File.expand_path(File.join(__dir__, '..', 'build', lib_name))
    return default_path if File.exist?(default_path)

    # Fallback to standard system paths if not in build directory
    lib_name
  end

  # Represents a single directory mount inside the sandbox.
  class SandboxMount < FFI::Struct
    layout :dir, :pointer,
           :read_only, :int
  end

  # Configuration parameters for a sandbox execution.
  class SandboxConfig < FFI::Struct
    layout :mounts, :pointer,
           :mount_count, :size_t,
           :disable_network, :int,
           :env_vars, :pointer,
           :env_count, :size_t,
           :timeout_secs, :uint,
           :stdout_buffer, :pointer,
           :stdout_size, :pointer,
           :stderr_buffer, :pointer,
           :stderr_size, :pointer,
           :max_memory_mb, :uint,
           :max_cpu_percent, :uint,
           :drop_privileges, :int,
           :target_uid, :uint,
           :target_gid, :uint,
           :denied_syscalls, :pointer,
           :denied_syscall_count, :size_t,
           :seccomp_profile_path, :pointer,
           :apparmor_profile, :pointer,
           :use_pty, :int,
           :max_network_mbps, :uint
  end

  # Function pointer signatures for the engine struct
  callback :init_func, [], :int
  callback :execute_func, [:pointer, :int, :pointer, :pointer], :int
  callback :execute_async_func, [:pointer, :int, :pointer, :pointer], :int
  callback :wait_process_func, [:pointer, :pointer], :int
  callback :free_process_func, [:pointer], :int
  callback :cleanup_func, [], :int

  # Defines the interface for a specific sandbox implementation.
  class SandboxEngine < FFI::Struct
    layout :engine_name, :string,
           :description, :string,
           :init, :init_func,
           :execute, :execute_func,
           :execute_async, :execute_async_func,
           :wait_process, :wait_process_func,
           :free_process, :free_process_func,
           :cleanup, :cleanup_func
  end

  # High-level wrapper class for executing commands in the sandbox.
  class SandboxWrapper
    def initialize(lib_path = nil)
      resolved_path = LibMountSandbox.resolve_lib_path(lib_path)

      @mod = Module.new do
        extend FFI::Library
        ffi_lib resolved_path
        attach_function :get_sandbox_engine, [:string, :pointer], :int
      end
    end

    # Executes a command within the specified sandbox engine.
    #
    # @param engine_name [String] The name of the engine (e.g., "dummy", "docker", "native").
    # @param command_args [Array<String>] The command and its arguments to execute.
    # @param config [SandboxConfig, nil] Optional sandbox configuration struct.
    # @return [Integer] The exit status of the command.
    def execute(engine_name, command_args, config = nil)
      engine_out_ptr = FFI::MemoryPointer.new(:pointer)
      rc = @mod.get_sandbox_engine(engine_name, engine_out_ptr)
      engine_ptr = engine_out_ptr.read_pointer
      if rc != 0 || engine_ptr.null?
        raise ArgumentError, "Engine '#{engine_name}' not found."
      end

      engine = SandboxEngine.new(engine_ptr)

      init_func = engine[:init]
      execute_func = engine[:execute]
      cleanup_func = engine[:cleanup]

      if init_func.call != 0
        raise RuntimeError, "Failed to initialize engine '#{engine_name}'."
      end

      argc = command_args.length
      argv = FFI::MemoryPointer.new(:pointer, argc + 1)

      # Keep references to string pointers so GC doesn't collect them during execution
      str_ptrs = command_args.map { |arg| FFI::MemoryPointer.from_string(arg) }
      str_ptrs.each_with_index do |ptr, i|
        argv[i].put_pointer(0, ptr)
      end
      argv[argc].put_pointer(0, nil)

      cfg = config
      if cfg.nil?
        cfg = SandboxConfig.new
        cfg.pointer.clear # Zero out the entire struct memory
      end

      status_ptr = FFI::MemoryPointer.new(:int)
      status_ptr.write_int(0)
      exec_rc = execute_func.call(cfg.to_ptr, argc, argv, status_ptr)
      cleanup_func.call

      return -1 if exec_rc != 0
      status_ptr.read_int
    end
  end
end
