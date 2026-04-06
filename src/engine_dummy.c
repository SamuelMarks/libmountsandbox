#include <stdlib.h>
/**
 * \file engine_dummy.c
 * \brief A minimal dummy sandbox engine used strictly for unit testing.
 */

#include "sandbox.h"

/**
 * \brief Initializes the dummy engine.
 * \return 0 to indicate successful initialization.
 */
static int dummy_init(void) {
    return 0;
}

/**
 * \brief Executes a command using the dummy engine.
 * 
 * Does not actually execute any command, but allows testing of parameter
 * passing across the sandbox interface.
 * 
 * \param config The sandbox configuration parameters.
 * \param argc Number of arguments.
 * \param argv Argument list.
 * \return Always 0.
 */
static int dummy_execute(const sandbox_config_t *config, int argc, char **argv) {
    /* Cast to void to ignore unused parameter warnings in strict C89 */
    (void)config;
    (void)argc;
    (void)argv;
    return 0;
}

/**
 * \brief Cleans up the dummy engine resources.
 */

struct sandbox_process_t {
    int dummy_field;
};

static sandbox_process_t* dummy_execute_async(const sandbox_config_t *config, int argc, char **argv) {
    sandbox_process_t *proc = (sandbox_process_t *)malloc(sizeof(sandbox_process_t));
    if (proc) {
        proc->dummy_field = 0; /* Just run it synchronously for the dummy mock */
        proc->dummy_field = dummy_execute(config, argc, argv);
    }
    return proc;
}

static int dummy_wait_process(sandbox_process_t *process, int *exit_status) {
    if (!process || !exit_status) return -1;
    *exit_status = process->dummy_field;
    return 0;
}

static void dummy_free_process(sandbox_process_t *process) {
    if (process) free(process);
}

static void dummy_cleanup(void) {
    /* No cleanup required */
}

/**
 * \brief The dummy engine export.
 */
sandbox_engine_t engine_dummy = {
    "dummy",
    "Dummy engine for testing abstraction",
    dummy_init,
    dummy_execute,
    dummy_execute_async,
    dummy_wait_process,
    dummy_free_process,
    dummy_cleanup
};
