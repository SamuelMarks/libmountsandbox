require 'ffi'

# The LibMountSandbox module provides a Ruby FFI wrapper around the C libmountsandbox library.
module LibMountSandbox
  extend FFI::Library

  # Helper method to dynamically resolve the shared library path based on the host OS.
  # @param lib_path [String, nil] An optional override path to the shared library.
  # @return [String] The resolved absolute path to the shared library.
  def self.resolve_lib_path(lib_path = nil)
    return lib_path if lib_path

    lib_name = case RbConfig::CONFIG['host_os']
               when /darwin/ then 'libmountsandbox.dylib'
               when /mswin|msys|mingw|cygwin|bccwin|wince|emc/ then 'mountsandbox.dll'
               else 'libmountsandbox.so'
               end

    File.expand_path("../../build/#{lib_name}", __FILE__)
  end

  # Represents a single directory mount inside the sandbox.
  class SandboxMount < FFI::Struct
    layout :dir, :string,
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
           :seccomp_profile_path, :string,
           :apparmor_profile, :string,
           :use_pty, :int,
           :max_network_mbps, :uint
  end

  # Defines the interface for a specific sandbox implementation.
  class SandboxEngine < FFI::Struct
    layout :engine_name, :string,
           :description, :string,
           :init, :pointer,
           :execute, :pointer,
           :execute_async, :pointer,
           :wait_process, :pointer,
           :free_process, :pointer,
           :cleanup, :pointer
  end

  # The SandboxWrapper is the main class used to execute commands via the FFI.
  class SandboxWrapper
    # Initializes the sandbox wrapper.
    # @param lib_path [String, nil] An optional path to the libmountsandbox shared library.
    def initialize(lib_path = nil)
      @lib_path = LibMountSandbox.resolve_lib_path(lib_path)
      
      # We load the library into an anonymous module to isolate state if needed,
      # but FFI::Library is typically used at the module level.
      # To match the Python API, we do it here:
      @lib = Module.new do
        extend FFI::Library
      end
      @lib.ffi_lib @lib_path
      @lib.attach_function :get_sandbox_engine, [:string, :pointer], :int
    end

    # Executes a command within the sandboxed environment.
    # @param engine_name [String] The name of the engine (e.g. 'native').
    # @param command_args [Array<String>] The command arguments to execute.
    # @param config [SandboxConfig, nil] The sandbox configuration (optional).
    # @return [Integer] The exit status of the executed command.
    def execute(engine_name, command_args, config = nil)
      engine_ptr_ptr = FFI::MemoryPointer.new(:pointer)
      res = @lib.get_sandbox_engine(engine_name, engine_ptr_ptr)

      if res != 0 || engine_ptr_ptr.null? || engine_ptr_ptr.read_pointer.null?
        raise ArgumentError, "Unknown sandbox engine: #{engine_name}"
      end

      engine = SandboxEngine.new(engine_ptr_ptr.read_pointer)

      init_func = FFI::Function.new(:int, [], engine[:init])
      execute_func = FFI::Function.new(:int, [:pointer, :int, :pointer], engine[:execute])
      cleanup_func = FFI::Function.new(:void, [], engine[:cleanup])

      if init_func.call != 0
        raise RuntimeError, "Failed to initialize engine: #{engine_name}"
      end

      argc = command_args.length
      argv = FFI::MemoryPointer.new(:pointer, argc)
      
      # Keep references to string pointers so they aren't garbage collected during the call
      str_ptrs = command_args.map { |arg| FFI::MemoryPointer.from_string(arg) }
      argv.write_array_of_pointer(str_ptrs)

      cfg = config
      if cfg.nil?
        cfg = SandboxConfig.new
        cfg.pointer.clear # Zero out the entire struct memory
      end

      status = execute_func.call(cfg.to_ptr, argc, argv)
      cleanup_func.call
      
      status
    end
  end
end
