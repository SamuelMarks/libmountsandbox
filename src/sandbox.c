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
  int rc = 0;
  
  if (engine_out) {
    *engine_out = NULL;
  }

  if (!name || !engine_out) {
    rc = -1;
    return rc;
  }

  if (strcmp(name, "dummy") == 0) {
    *engine_out = &engine_dummy;
    return rc;
  }

  if (strcmp(name, "docker") == 0) {
    *engine_out = &engine_docker;
    return rc;
  }

  if (strcmp(name, "podman") == 0) {
    *engine_out = &engine_podman;
    return rc;
  }

  if (strcmp(name, "gvisor") == 0) {
    *engine_out = &engine_gvisor;
    return rc;
  }

  if (strcmp(name, "wasmtime") == 0) {
    *engine_out = &engine_wasmtime;
    return rc;
  }

  if (strcmp(name, "appcontainer") == 0) {
    *engine_out = &engine_appcontainer;
    return rc;
  }

  if (strcmp(name, "native") == 0) {
    *engine_out = &engine_native;
    return rc;
  }

  *engine_out = NULL;
  rc = -1;
  return rc;
}
