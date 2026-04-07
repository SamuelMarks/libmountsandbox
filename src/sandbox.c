/* clang-format off */
#include "sandbox.h"
#include <string.h>

/* clang-format on */
/**
 * \brief Retrieves a sandbox engine instance by its short name.
 * \param name The string name of the engine to retrieve.
 * \param engine_out Pointer to a sandbox_engine_t pointer to receive the
 * result.
 * \return 0 on success, or -1 if the engine is not found.
 */
int get_sandbox_engine(const char *name, sandbox_engine_t **engine_out) {
  if (engine_out) {
    *engine_out = NULL;
  }

  if (!name || !engine_out) {
    return -1;
  }

  if (strcmp(name, "dummy") == 0) {
    *engine_out = &engine_dummy;
    return 0;
  }

  if (strcmp(name, "docker") == 0) {
    *engine_out = &engine_docker;
    return 0;
  }

  if (strcmp(name, "podman") == 0) {
    *engine_out = &engine_podman;
    return 0;
  }

  if (strcmp(name, "gvisor") == 0) {
    *engine_out = &engine_gvisor;
    return 0;
  }

  if (strcmp(name, "wasmtime") == 0) {
    *engine_out = &engine_wasmtime;
    return 0;
  }

  if (strcmp(name, "appcontainer") == 0) {
    *engine_out = &engine_appcontainer;
    return 0;
  }

  if (strcmp(name, "native") == 0) {
    *engine_out = &engine_native;
    return 0;
  }

  *engine_out = NULL;
  return -1;
}
