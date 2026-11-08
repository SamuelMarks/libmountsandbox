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
#endif /* __cplusplus */

/* clang-format off */
#include <stddef.h>
/* clang-format on */

#if defined(__cplusplus) && __cplusplus >= 201703L
/** \brief Compiler attribute to warn when a return value is discarded. */
#define NO_DISCARD [[nodiscard]]
#elif defined(__GNUC__) || defined(__clang__)
/** \brief Compiler attribute to warn when a return value is discarded. */
#define NO_DISCARD __attribute__((warn_unused_result))
#elif defined(_MSC_VER) && _MSC_VER >= 1700
/** \brief Compiler attribute to warn when a return value is discarded. */
#define NO_DISCARD _Check_return_
#else
/** \brief Compiler attribute to warn when a return value is discarded. */
#define NO_DISCARD
#endif

/**
 * \brief Error codes returned by all libmountsandbox functions.
 */
typedef enum sandbox_error {
  /** \brief Operation completed successfully. */
  SANDBOX_SUCCESS = 0,
  /** \brief Invalid or NULL argument provided. */
  SANDBOX_ERR_INVALID_ARG = 1,
  /** \brief Memory allocation failed (out of memory). */
  SANDBOX_ERR_OUT_OF_MEMORY = 2,
  /** \brief Requested sandbox engine was not found. */
  SANDBOX_ERR_NOT_FOUND = 3,
  /** \brief Requested feature or platform is not supported. */
  SANDBOX_ERR_UNSUPPORTED = 4,
  /** \brief Sandbox command execution or OS API call failed. */
  SANDBOX_ERR_EXEC_FAILED = 5,
  /** \brief Input/output or temporary stream operation failed. */
  SANDBOX_ERR_IO = 6
} sandbox_error_t;

/**
 * \brief Opaque handle representing an asynchronously running sandboxed
 * process.
 */
typedef struct sandbox_process_t sandbox_process_t;

/**
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

  /** \brief Target UID if drop_privileges is set. */
  unsigned int target_uid;

  /** \brief Target GID if drop_privileges is set. */
  unsigned int target_gid;

  /** \brief Array of syscall names to filter/deny. */
  const char **denied_syscalls;

  /** \brief Number of syscalls in the denied_syscalls array. */
  size_t denied_syscall_count;

  /** \brief Optional path to a custom Seccomp BPF profile (JSON for Docker, BPF
   * for Native). */
  const char *seccomp_profile_path;

  /** \brief Optional name of a custom AppArmor profile. */
  const char *apparmor_profile;

  /** \brief Boolean flag (1=true, 0=false) to allocate a pseudo-terminal (PTY)
   * for the sandbox. */
  int use_pty;

  /** \brief Maximum network bandwidth in Mbps. 0 means unlimited. */
  unsigned int max_network_mbps;
} sandbox_config_t;

/**
 * \brief Defines the interface for a specific sandbox implementation.
 */
typedef struct {
  /** \brief Short identifier for the engine (e.g., "docker", "podman",
   * "gvisor", "native"). */
  const char *engine_name;

  /** \brief Human-readable description of the engine. */
  const char *description;

  /**
   * \brief Initializes the sandbox engine.
   * \return SANDBOX_SUCCESS on success, or an error enum on failure.
   */
  sandbox_error_t (*init)(void);

  /**
   * \brief Executes a command within the sandboxed environment.
   * \param config The sandbox configuration parameters.
   * \param argc The number of command arguments.
   * \param argv The command arguments array (null-terminated).
   * \param exit_status Pointer to store the exit code of the executed command.
   * \return SANDBOX_SUCCESS on success, or an error enum on internal error.
   */
  sandbox_error_t (*execute)(const sandbox_config_t *config, int argc,
                             char **argv, int *exit_status);

  /**
   * \brief Executes a command within the sandboxed environment asynchronously.
   * \param config The sandbox configuration parameters.
   * \param argc The number of command arguments.
   * \param argv The command arguments array (null-terminated).
   * \param out_process Pointer to receive the allocated process handle.
   * \return SANDBOX_SUCCESS on success, or an error enum on internal error.
   */
  sandbox_error_t (*execute_async)(const sandbox_config_t *config, int argc,
                                   char **argv,
                                   sandbox_process_t **out_process);

  /**
   * \brief Waits for an asynchronously executing sandboxed process to finish.
   * \param process The process handle returned by execute_async.
   * \param exit_status Pointer to receive the process exit code.
   * \return SANDBOX_SUCCESS on success, or an error enum on internal error.
   */
  sandbox_error_t (*wait_process)(sandbox_process_t *process, int *exit_status);

  /**
   * @brief Frees the resources associated with an asynchronous process handle.
   * @param process The process handle.
   * @return SANDBOX_SUCCESS on success, or an error enum on failure.
   */
  sandbox_error_t (*free_process)(sandbox_process_t *process);

  /**
   * @brief Cleans up any resources allocated by the engine.
   * @return SANDBOX_SUCCESS on success, or an error enum on failure.
   */
  sandbox_error_t (*cleanup)(void);
} sandbox_engine_t;

/**
 * \brief Retrieves a sandbox engine instance by its short name.
 * \param name The string name of the engine to retrieve.
 * \param engine_out Pointer to store the resulting sandbox_engine_t pointer.
 * \return SANDBOX_SUCCESS on success, or an error enum if not found or invalid.
 */
NO_DISCARD sandbox_error_t get_sandbox_engine(const char *name,
                                              sandbox_engine_t **engine_out);

/** \brief The dummy engine used for unit testing. */
extern sandbox_engine_t engine_dummy;

/** \brief The Docker engine used for container-based sandboxing. */
extern sandbox_engine_t engine_docker;

/** \brief The Podman engine used for rootless container sandboxing. */
extern sandbox_engine_t engine_podman;

/** \brief The gVisor (runsc) engine used for strongly isolated container
 * sandboxing. */
extern sandbox_engine_t engine_gvisor;

/** \brief The Wasmtime engine used for WebAssembly WASI sandboxing. */
extern sandbox_engine_t engine_wasmtime;

/** \brief The Native Windows AppContainer engine. */
extern sandbox_engine_t engine_appcontainer;

/** \brief The Native engine leveraging host-OS native isolation features. */
extern sandbox_engine_t engine_native;

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* SANDBOX_H */
