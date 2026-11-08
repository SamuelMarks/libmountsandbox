/**
 * \file sandbox.c
 * \brief Sandbox engine registry and lookup implementation.
 */
/* clang-format off */
#include "sandbox.h"
#include <string.h>
/* clang-format on */

/**
 * \brief Retrieves a sandbox engine instance by its short name.
 * \param name The string name of the engine to retrieve.
 * \param engine_out Pointer to store the resulting sandbox_engine_t pointer.
 * \return SANDBOX_SUCCESS on success, or an error enum if not found or invalid.
 */
sandbox_error_t get_sandbox_engine(const char *name,
                                   sandbox_engine_t **engine_out) {
  if (!engine_out) {
    return SANDBOX_ERR_INVALID_ARG;
  }
  if (!name) {
    *engine_out = NULL;
    return SANDBOX_ERR_INVALID_ARG;
  }

  if (strcmp(name, "dummy") == 0) {
    *engine_out = &engine_dummy;
    return SANDBOX_SUCCESS;
  }

  if (strcmp(name, "docker") == 0) {
    *engine_out = &engine_docker;
    return SANDBOX_SUCCESS;
  }

  if (strcmp(name, "podman") == 0) {
    *engine_out = &engine_podman;
    return SANDBOX_SUCCESS;
  }

  if (strcmp(name, "gvisor") == 0) {
    *engine_out = &engine_gvisor;
    return SANDBOX_SUCCESS;
  }

  if (strcmp(name, "wasmtime") == 0) {
    *engine_out = &engine_wasmtime;
    return SANDBOX_SUCCESS;
  }

  if (strcmp(name, "appcontainer") == 0) {
    *engine_out = &engine_appcontainer;
    return SANDBOX_SUCCESS;
  }

  if (strcmp(name, "native") == 0) {
    *engine_out = &engine_native;
    return SANDBOX_SUCCESS;
  }

  *engine_out = NULL;
  return SANDBOX_ERR_NOT_FOUND;
}
