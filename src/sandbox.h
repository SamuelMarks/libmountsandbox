/**
 * \file sandbox.h
 * \brief Sandbox engine abstraction for executing commands in isolated
 * environments.
 *
 * This file defines the core `sandbox_engine_t` interface used to abstract
 * underlying sandboxing mechanisms (Docker, native namespaces, job objects,
 * etc.) across multiple platforms natively in C89.
 */
#ifndef SANDBOX_H
#define SANDBOX_H
#ifdef __cplusplus
extern "C" {
#endif

/* clang-format off */
#include <stddef.h>

/* clang-format on */
/**
 * \struct sandbox_mount_t
 * \brief Represents a single directory mount inside the sandbox.
 */
typedef struct {
  /** \brief The directory path on the host to mount. */
  const char *dir;

  /** \brief Boolean flag (1=true, 0=false) indicating if the mount is
   * read-only. */
  int read_only;
} sandbox_mount_t;

/**
 * \struct sandbox_config_t
 * \brief Configuration parameters for a sandbox execution.
 */
typedef struct {
  /** \brief Array of mount points to expose in the sandbox. */
  const sandbox_mount_t *mounts;

  /** \brief Number of mounts in the mounts array. */
  size_t mount_count;

  /** \brief Boolean flag (1=true, 0=false) to disable network access in the
   * sandbox. */
  int disable_network;

  /** \brief Array of environment variable strings in "KEY=VALUE" format. */
  const char **env_vars;

  /** \brief Number of environment variables in env_vars. */
  size_t env_count;

  /** \brief Execution timeout in seconds. A value of 0 means no timeout. */
  unsigned int timeout_secs;

  /** \brief Optional pointer to a buffer that will be allocated and filled with
   * stdout. */
  char **stdout_buffer;

  /** \brief Optional pointer to a size_t that will contain the length of
   * stdout_buffer. */
  size_t *stdout_size;

  /** \brief Optional pointer to a buffer that will be allocated and filled with
   * stderr. */
  char **stderr_buffer;

  /** \brief Optional pointer to a size_t that will contain the length of
   * stderr_buffer. */
  size_t *stderr_size;

  /** \brief Maximum memory limit in Megabytes. 0 means no limit. */
  unsigned int max_memory_mb;

  /** \brief Maximum CPU limit in percent (e.g., 100 = 1 full core). 0 means no
   * limit. */
  unsigned int max_cpu_percent;

  /** \brief Boolean flag (1=true, 0=false) to drop to a restricted user
   * namespace or unprivileged UID. */
  int drop_privileges;

  /** \brief Target UID if drop_privileges is set (ignored on platforms without
   * UID). Default 0 means nobody/dynamic. */
  unsigned int target_uid;

  /** \brief Target GID if drop_privileges is set (ignored on platforms without
   * GID). Default 0 means nobody/dynamic. */
  unsigned int target_gid;

  /** \brief Array of syscall names to filter/deny (Syscall filtering/Seccomp).
   */
  const char **denied_syscalls;

  /** \brief Number of syscalls in the denied_syscalls array. */
  size_t denied_syscall_count;

  /** \brief Optional path to a custom Seccomp BPF profile (JSON for Docker, BPF
   * for Native). */
  const char *seccomp_profile_path;

  /** \brief Optional name of a custom AppArmor profile. */
  const char *apparmor_profile;

  /** \brief Boolean flag (1=true, 0=false) to allocate a pseudo-terminal (PTY)
   * for the sandbox. Merges stderr into stdout. */
  int use_pty;

  /** \brief Maximum network bandwidth in Mbps. 0 means unlimited. */
  unsigned int max_network_mbps;
} sandbox_config_t;

/**
 * \struct sandbox_process_t
 * \brief Opaque handle representing an asynchronously executing sandbox
 * process.
 */
typedef struct sandbox_process_t sandbox_process_t;

/**
 * \struct sandbox_engine_t
 * \brief Defines the interface for a specific sandbox implementation.
 */
typedef struct {
  /** \brief Short identifier for the engine (e.g., "docker", "native"). */
  const char *engine_name;

  /** \brief Human-readable description of the engine. */
  const char *description;

  /**
   * \brief Initializes the sandbox engine.
   * \return 0 on success, non-zero on failure.
   */
  int (*init)(void);

  /**
   * \brief Executes a command within the sandboxed environment.
   * \param config The sandbox configuration parameters.
   * \param argc The number of command arguments.
   * \param argv The array of command arguments.
   * \return The exit status of the executed command, or -1 on system error.
   */
  int (*execute)(const sandbox_config_t *config, int argc, char **argv);

  /**
   * \brief Executes a command asynchronously within the sandboxed environment.
   * \param config The sandbox configuration parameters.
   * \param argc The number of command arguments.
   * \param argv The array of command arguments.
   * \param out_process Pointer to store the opaque handle to the running
   * process.
   * \return 0 on success, or -1 on error.
   */
  int (*execute_async)(const sandbox_config_t *config, int argc, char **argv,
                       sandbox_process_t **out_process);

  /**
   * \brief Waits for an asynchronously executing sandboxed process to complete.
   * \param process The opaque handle returned by execute_async.
   * \param exit_status Pointer to an integer where the exit code will be
   * stored.
   * \return 0 on success, or -1 on error.
   */
  int (*wait_process)(sandbox_process_t *process, int *exit_status);

  /**
   * \brief Frees an opaque handle returned by execute_async.
   * \param process The opaque handle to free.
   */
  void (*free_process)(sandbox_process_t *process);

  /**
   * \brief Cleans up any resources allocated by the engine.
   */
  void (*cleanup)(void);
} sandbox_engine_t;

/**
 * \brief Retrieves a sandbox engine instance by its short name.
 * \param name The string name of the engine to retrieve.
 * \return Pointer to the engine, or NULL if the engine is not found.
 */
int get_sandbox_engine(const char *name, sandbox_engine_t **engine_out);

/* Declarations of natively supported engines */

/** \brief The dummy engine used primarily for testing abstractions. */
extern sandbox_engine_t engine_dummy;

/** \brief The Docker engine that isolates execution via containerization. */
extern sandbox_engine_t engine_docker;

/** \brief The Podman engine that isolates execution via daemonless
 * containerization. */
extern sandbox_engine_t engine_podman;

/** \brief The gVisor engine that isolates execution via runsc userspace kernel.
 */
extern sandbox_engine_t engine_gvisor;

/** \brief The Wasmtime engine that executes WebAssembly via WASI. */
extern sandbox_engine_t engine_wasmtime;

/** \brief The Native Windows AppContainer engine. */
extern sandbox_engine_t engine_appcontainer;

/** \brief The Native engine leveraging host-OS native isolation features. */
extern sandbox_engine_t engine_native;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SANDBOX_H */
