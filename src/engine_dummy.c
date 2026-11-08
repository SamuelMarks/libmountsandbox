/**
 * \file engine_dummy.c
 * \brief A minimal dummy sandbox engine used strictly for unit testing.
 */
/* clang-format off */
#include "sandbox.h"
#include "sandbox_common.h"
#include <stdlib.h>
/* clang-format on */

/**
 * \brief Internal state for an asynchronous dummy process.
 */
struct sandbox_process_t {
  /** \brief Stored exit status of the dummy process. */
  int dummy_field;
};

/**
 * \brief Initializes the dummy engine.
 * \return SANDBOX_SUCCESS on initialization.
 */
static sandbox_error_t dummy_init(void) { return SANDBOX_SUCCESS; }

/**
 * \brief Executes a command using the dummy engine.
 * \param config The sandbox configuration parameters.
 * \param argc Number of arguments.
 * \param argv Argument list.
 * \param exit_status Pointer to store the command exit code.
 * \return SANDBOX_SUCCESS on success, or SANDBOX_ERR_INVALID_ARG on invalid
 * arguments.
 */
static sandbox_error_t dummy_execute(const sandbox_config_t *config, int argc,
                                     char **argv, int *exit_status) {
  if (!config || argc < 0 || !argv) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  if (exit_status) {
    *exit_status = 0;
  }
  return SANDBOX_SUCCESS;
}

/**
 * \brief Executes a command in the sandbox asynchronously.
 * \param config Sandbox configuration.
 * \param argc Argument count.
 * \param argv Argument vector.
 * \param out_process Pointer to receive the process handle.
 * \return SANDBOX_SUCCESS on success, or an error enum on failure.
 */
static sandbox_error_t dummy_execute_async(const sandbox_config_t *config,
                                           int argc, char **argv,
                                           sandbox_process_t **out_process) {
  sandbox_error_t rc;
  void *raw_proc = NULL;
  sandbox_process_t *proc;
  if (!config || argc < 0 || !argv || !out_process) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  rc = sandbox_alloc(sizeof(sandbox_process_t), &raw_proc);
  if (rc != SANDBOX_SUCCESS) {
    *out_process = NULL;
    return rc;
  }
  proc = (sandbox_process_t *)raw_proc;
  proc->dummy_field = 0;
  *out_process = proc;
  return dummy_execute(config, argc, argv, &proc->dummy_field);
}

/**
 * @brief Waits for an asynchronous process to complete.
 * @param process The process handle.
 * @param exit_status Pointer to receive the exit status.
 * @return SANDBOX_SUCCESS on success, or SANDBOX_ERR_INVALID_ARG on invalid
 * arguments.
 */
static sandbox_error_t dummy_wait_process(sandbox_process_t *process,
                                          int *exit_status) {
  if (!process || !exit_status) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  *exit_status = process->dummy_field;
  return SANDBOX_SUCCESS;
}

/**
 * @brief Frees an asynchronous process handle.
 * @param process The process handle.
 * @return SANDBOX_SUCCESS on completion.
 */
static sandbox_error_t dummy_free_process(sandbox_process_t *process) {
  if (process) {
    free(process);
  }
  return SANDBOX_SUCCESS;
}

/**
 * \brief Cleans up the engine resources.
 * \return SANDBOX_SUCCESS on completion.
 */
static sandbox_error_t dummy_cleanup(void) { return SANDBOX_SUCCESS; }

/**
 * \brief The dummy engine export.
 */
sandbox_engine_t engine_dummy = {"dummy",
                                 "Dummy engine for testing abstraction",
                                 dummy_init,
                                 dummy_execute,
                                 dummy_execute_async,
                                 dummy_wait_process,
                                 dummy_free_process,
                                 dummy_cleanup};
