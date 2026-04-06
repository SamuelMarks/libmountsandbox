using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;

namespace MountSandbox
{
    /// <summary>
    /// Represents a single directory mount inside the sandbox.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SandboxMountT
    {
        public IntPtr dir;
        public int read_only;
    }

    /// <summary>
    /// Configuration parameters for a sandbox execution.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SandboxConfigT
    {
        public IntPtr mounts;
        public UIntPtr mount_count;
        public int disable_network;
        public IntPtr env_vars;
        public UIntPtr env_count;
        public uint timeout_secs;
        public IntPtr stdout_buffer;
        public IntPtr stdout_size;
        public IntPtr stderr_buffer;
        public IntPtr stderr_size;
        public uint max_memory_mb;
        public uint max_cpu_percent;
        public int drop_privileges;
        public uint target_uid;
        public uint target_gid;
        public IntPtr denied_syscalls;
        public UIntPtr denied_syscall_count;
        public IntPtr seccomp_profile_path;
        public IntPtr apparmor_profile;
        public int use_pty;
        public uint max_network_mbps;
    }

    /// <summary>
    /// Defines the interface for a specific sandbox implementation.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct SandboxEngineT
    {
        public IntPtr engine_name;
        public IntPtr description;
        public IntPtr init;
        public IntPtr execute;
        public IntPtr execute_async;
        public IntPtr wait_process;
        public IntPtr free_process;
        public IntPtr cleanup;
    }

    /// <summary>
    /// P/Invoke methods for the libmountsandbox native library.
    /// </summary>
    internal static class NativeMethods
    {
        private const string LibName = "mountsandbox";

        [DllImport(LibName, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        public static extern int get_sandbox_engine(string name, out IntPtr engine_out);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int InitDelegate();

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate int ExecuteDelegate(ref SandboxConfigT config, int argc, IntPtr argv);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        public delegate void CleanupDelegate();
        
        [DllImport("libc", EntryPoint="free", CallingConvention = CallingConvention.Cdecl)]
        public static extern void libc_free(IntPtr ptr);
        
        [DllImport("msvcrt", EntryPoint="free", CallingConvention = CallingConvention.Cdecl)]
        public static extern void msvcrt_free(IntPtr ptr);
    }

    /// <summary>
    /// Exception thrown when a sandbox operation fails.
    /// </summary>
    public class SandboxException : Exception
    {
        public SandboxException(string message) : base(message) { }
    }

    /// <summary>
    /// Describes a directory to mount into the sandbox environment.
    /// </summary>
    public struct MountInfo
    {
        /// <summary>
        /// The path to the directory on the host.
        /// </summary>
        public string Dir;
        /// <summary>
        /// Whether the mount should be read-only.
        /// </summary>
        public bool ReadOnly;
    }

    /// <summary>
    /// Encapsulates the results of a sandbox execution.
    /// </summary>
    public class ExecutionResult
    {
        /// <summary>
        /// The exit code of the sandboxed process.
        /// </summary>
        public int ExitCode { get; set; }
        /// <summary>
        /// The standard output of the process.
        /// </summary>
        public string StdOut { get; set; }
        /// <summary>
        /// The standard error of the process.
        /// </summary>
        public string StdErr { get; set; }
    }

    /// <summary>
    /// A wrapper class for interacting with a specific sandbox engine.
    /// </summary>
    public class Sandbox : IDisposable
    {
        private IntPtr _enginePtr;
        private SandboxEngineT _engine;
        private bool _disposed = false;

        /// <summary>
        /// Initializes a new instance of the Sandbox engine.
        /// </summary>
        /// <param name="engineName">The name of the engine (e.g., "native", "docker", "podman", "gvisor", "dummy").</param>
        public Sandbox(string engineName)
        {
            int res = NativeMethods.get_sandbox_engine(engineName, out _enginePtr);
            if (res != 0 || _enginePtr == IntPtr.Zero)
            {
                throw new SandboxException($"Unknown sandbox engine: {engineName}");
            }

            _engine = Marshal.PtrToStructure<SandboxEngineT>(_enginePtr);

            if (_engine.init != IntPtr.Zero)
            {
                var initDelegate = Marshal.GetDelegateForFunctionPointer<NativeMethods.InitDelegate>(_engine.init);
                int initRes = initDelegate();
                if (initRes != 0)
                {
                    throw new SandboxException($"Failed to initialize engine: {engineName}");
                }
            }
        }

        ~Sandbox()
        {
            Dispose(false);
        }

        /// <summary>
        /// Disposes the sandbox engine and runs its cleanup routine.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (_enginePtr != IntPtr.Zero && _engine.cleanup != IntPtr.Zero)
                {
                    var cleanupDelegate = Marshal.GetDelegateForFunctionPointer<NativeMethods.CleanupDelegate>(_engine.cleanup);
                    cleanupDelegate();
                }
                _disposed = true;
            }
        }

        /// <summary>
        /// Executes a command inside the sandbox.
        /// </summary>
        /// <param name="commandArgs">The command and its arguments.</param>
        /// <param name="mounts">A list of directories to mount.</param>
        /// <param name="envVars">A list of environment variables in KEY=VALUE format.</param>
        /// <param name="disableNetwork">If true, networking is disabled.</param>
        /// <param name="timeoutSecs">Timeout in seconds before the process is killed.</param>
        /// <param name="maxMemoryMb">Memory limit in MB.</param>
        /// <param name="maxCpuPercent">CPU limit in percent.</param>
        /// <param name="dropPrivileges">If true, privileges are dropped.</param>
        /// <param name="targetUid">The UID to drop to.</param>
        /// <param name="targetGid">The GID to drop to.</param>
        /// <param name="deniedSyscalls">A list of syscalls or capabilities to drop.</param>
        /// <param name="captureOutput">If true, standard output and error are captured and returned.</param>
        /// <returns>An ExecutionResult containing the exit code and outputs.</returns>
        public ExecutionResult Execute(string[] commandArgs, 
                                       List<MountInfo> mounts = null,
                                       List<string> envVars = null,
                                       bool disableNetwork = false,
                                       uint timeoutSecs = 0,
                                       uint maxMemoryMb = 0,
                                       uint maxCpuPercent = 0,
                                       bool dropPrivileges = false,
                                       uint targetUid = 0,
                                       uint targetGid = 0,
                                       List<string> deniedSyscalls = null,
                                       string seccompProfilePath = null,
                                       string apparmorProfile = null,
                                       bool usePty = false,
                                       uint maxNetworkMbps = 0,
                                       bool captureOutput = true)
        {
            if (_disposed) throw new ObjectDisposedException("Sandbox");

            var config = new SandboxConfigT();

            // Mounts
            IntPtr mountsArray = IntPtr.Zero;
            List<IntPtr> mountDirPtrs = new List<IntPtr>();
            if (mounts != null && mounts.Count > 0)
            {
                int mountSize = Marshal.SizeOf<SandboxMountT>();
                mountsArray = Marshal.AllocHGlobal(mounts.Count * mountSize);
                for (int i = 0; i < mounts.Count; i++)
                {
                    IntPtr dirPtr = Marshal.StringToHGlobalAnsi(mounts[i].Dir);
                    mountDirPtrs.Add(dirPtr);
                    
                    var sm = new SandboxMountT { dir = dirPtr, read_only = mounts[i].ReadOnly ? 1 : 0 };
                    Marshal.StructureToPtr(sm, mountsArray + i * mountSize, false);
                }
                config.mounts = mountsArray;
                config.mount_count = (UIntPtr)mounts.Count;
            }

            // Env Vars
            IntPtr envArray = IntPtr.Zero;
            List<IntPtr> envPtrs = new List<IntPtr>();
            if (envVars != null && envVars.Count > 0)
            {
                envArray = Marshal.AllocHGlobal(envVars.Count * IntPtr.Size);
                for (int i = 0; i < envVars.Count; i++)
                {
                    IntPtr envPtr = Marshal.StringToHGlobalAnsi(envVars[i]);
                    envPtrs.Add(envPtr);
                    Marshal.WriteIntPtr(envArray, i * IntPtr.Size, envPtr);
                }
                config.env_vars = envArray;
                config.env_count = (UIntPtr)envVars.Count;
            }

            // Syscalls
            IntPtr syscallArray = IntPtr.Zero;
            List<IntPtr> syscallPtrs = new List<IntPtr>();
            if (deniedSyscalls != null && deniedSyscalls.Count > 0)
            {
                syscallArray = Marshal.AllocHGlobal(deniedSyscalls.Count * IntPtr.Size);
                for (int i = 0; i < deniedSyscalls.Count; i++)
                {
                    IntPtr sysPtr = Marshal.StringToHGlobalAnsi(deniedSyscalls[i]);
                    syscallPtrs.Add(sysPtr);
                    Marshal.WriteIntPtr(syscallArray, i * IntPtr.Size, sysPtr);
                }
                config.denied_syscalls = syscallArray;
                config.denied_syscall_count = (UIntPtr)deniedSyscalls.Count;
            }

            config.disable_network = disableNetwork ? 1 : 0;
            config.timeout_secs = timeoutSecs;
            config.max_memory_mb = maxMemoryMb;
            config.max_cpu_percent = maxCpuPercent;
            config.drop_privileges = dropPrivileges ? 1 : 0;
            config.target_uid = targetUid;
            config.target_gid = targetGid;
            
            IntPtr pSeccomp = IntPtr.Zero;
            if (!string.IsNullOrEmpty(seccompProfilePath)) {
                pSeccomp = Marshal.StringToHGlobalAnsi(seccompProfilePath);
                config.seccomp_profile_path = pSeccomp;
            }
            
            IntPtr pApparmor = IntPtr.Zero;
            if (!string.IsNullOrEmpty(apparmorProfile)) {
                pApparmor = Marshal.StringToHGlobalAnsi(apparmorProfile);
                config.apparmor_profile = pApparmor;
            }
            config.use_pty = usePty ? 1 : 0;
            config.max_network_mbps = maxNetworkMbps;

            // Output capture
            IntPtr pStdoutBuffer = IntPtr.Zero;
            IntPtr pStdoutSize = IntPtr.Zero;
            IntPtr pStderrBuffer = IntPtr.Zero;
            IntPtr pStderrSize = IntPtr.Zero;

            if (captureOutput)
            {
                pStdoutBuffer = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(pStdoutBuffer, IntPtr.Zero);
                pStdoutSize = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(pStdoutSize, IntPtr.Zero);

                pStderrBuffer = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(pStderrBuffer, IntPtr.Zero);
                pStderrSize = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(pStderrSize, IntPtr.Zero);

                config.stdout_buffer = pStdoutBuffer;
                config.stdout_size = pStdoutSize;
                config.stderr_buffer = pStderrBuffer;
                config.stderr_size = pStderrSize;
            }

            // Args
            int argc = commandArgs.Length;
            IntPtr argv = Marshal.AllocHGlobal(argc * IntPtr.Size);
            List<IntPtr> argPtrs = new List<IntPtr>();
            for (int i = 0; i < argc; i++)
            {
                IntPtr argPtr = Marshal.StringToHGlobalAnsi(commandArgs[i]);
                argPtrs.Add(argPtr);
                Marshal.WriteIntPtr(argv, i * IntPtr.Size, argPtr);
            }

            int exitCode = -1;
            try
            {
                var executeDelegate = Marshal.GetDelegateForFunctionPointer<NativeMethods.ExecuteDelegate>(_engine.execute);
                exitCode = executeDelegate(ref config, argc, argv);
            }
            finally
            {
                // Free args
                foreach (var ptr in argPtrs) Marshal.FreeHGlobal(ptr);
                Marshal.FreeHGlobal(argv);

                // Free mounts
                foreach (var ptr in mountDirPtrs) Marshal.FreeHGlobal(ptr);
                if (mountsArray != IntPtr.Zero) Marshal.FreeHGlobal(mountsArray);

                // Free envs
                foreach (var ptr in envPtrs) Marshal.FreeHGlobal(ptr);
                if (envArray != IntPtr.Zero) Marshal.FreeHGlobal(envArray);

                // Free syscalls
                foreach (var ptr in syscallPtrs) Marshal.FreeHGlobal(ptr);
                if (syscallArray != IntPtr.Zero) Marshal.FreeHGlobal(syscallArray);
                if (pSeccomp != IntPtr.Zero) Marshal.FreeHGlobal(pSeccomp);
                if (pApparmor != IntPtr.Zero) Marshal.FreeHGlobal(pApparmor);
            }

            string stdoutStr = "";
            string stderrStr = "";

            if (captureOutput)
            {
                IntPtr stdoutBufPtr = Marshal.ReadIntPtr(pStdoutBuffer);
                if (stdoutBufPtr != IntPtr.Zero)
                {
                    stdoutStr = Marshal.PtrToStringAnsi(stdoutBufPtr);
                    FreeC(stdoutBufPtr);
                }

                IntPtr stderrBufPtr = Marshal.ReadIntPtr(pStderrBuffer);
                if (stderrBufPtr != IntPtr.Zero)
                {
                    stderrStr = Marshal.PtrToStringAnsi(stderrBufPtr);
                    FreeC(stderrBufPtr);
                }

                Marshal.FreeHGlobal(pStdoutBuffer);
                Marshal.FreeHGlobal(pStdoutSize);
                Marshal.FreeHGlobal(pStderrBuffer);
                Marshal.FreeHGlobal(pStderrSize);
            }

            return new ExecutionResult
            {
                ExitCode = exitCode,
                StdOut = stdoutStr,
                StdErr = stderrStr
            };
        }

        private void FreeC(IntPtr ptr)
        {
            if (ptr == IntPtr.Zero) return;
            try
            {
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                {
                    NativeMethods.msvcrt_free(ptr);
                }
                else
                {
                    NativeMethods.libc_free(ptr);
                }
            }
            catch
            {
                // Ignore fallback free issues
            }
        }
    }
}
