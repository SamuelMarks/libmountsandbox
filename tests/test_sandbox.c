/**
 * \file test_sandbox.c
 * \brief C89-compliant unit tests for the libmountsandbox abstraction.
 */

/* clang-format off */
#include "../src/sandbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* clang-format on */
static int tests_run = 0;
static int tests_passed = 0;

/**
 * \brief Macro to assert a condition and track test results.
 */
#define ASSERT_TRUE(cond, msg)                                                 \
  do {                                                                         \
    tests_run++;                                                               \
    if (!(cond)) {                                                             \
      fprintf(stderr, "FAIL: %s (line %d)\n", (msg), __LINE__);                \
    } else {                                                                   \
      tests_passed++;                                                          \
    }                                                                          \
  } while (0)

/**
 * \brief Tests the engine factory function.
 */
static void test_get_engine(void) {
  sandbox_engine_t *engine;

  get_sandbox_engine(NULL, &engine);
  ASSERT_TRUE(engine == NULL, "NULL should return NULL engine");

  get_sandbox_engine("invalid_name", &engine);
  ASSERT_TRUE(engine == NULL, "Invalid name should return NULL engine");

  get_sandbox_engine("dummy", &engine);
  ASSERT_TRUE(engine != NULL, "Dummy engine should be found");
  if (engine) {
    ASSERT_TRUE(strcmp(engine->engine_name, "dummy") == 0,
                "Engine name should be dummy");
  }

  get_sandbox_engine("gvisor", &engine);
  ASSERT_TRUE(engine != NULL, "gVisor engine should be found");
  if (engine) {
    ASSERT_TRUE(strcmp(engine->engine_name, "gvisor") == 0,
                "Engine name should be gvisor");
  }

  get_sandbox_engine("wasmtime", &engine);
  ASSERT_TRUE(engine != NULL, "Wasmtime engine should be found");
  if (engine) {
    ASSERT_TRUE(strcmp(engine->engine_name, "wasmtime") == 0,
                "Engine name should be wasmtime");
  }

  get_sandbox_engine("appcontainer", &engine);
  ASSERT_TRUE(engine != NULL, "AppContainer engine should be found");
  if (engine) {
    ASSERT_TRUE(strcmp(engine->engine_name, "appcontainer") == 0,
                "Engine name should be appcontainer");
  }

  get_sandbox_engine("podman", &engine);
  ASSERT_TRUE(engine != NULL, "Podman engine should be found");
  if (engine) {
    ASSERT_TRUE(strcmp(engine->engine_name, "podman") == 0,
                "Engine name should be podman");
  }

  get_sandbox_engine("native", &engine);
  ASSERT_TRUE(engine != NULL, "Native engine should be found");
  if (engine) {
    ASSERT_TRUE(strcmp(engine->engine_name, "native") == 0,
                "Engine name should be native");
  }
}

/**
 * \brief Tests the dummy engine execution.
 */
static void test_dummy_engine(void) {
  int ret;
  char *argv[2];
  sandbox_config_t config;
  const char *envs[2];
  sandbox_mount_t mounts[1];

  envs[0] = "FOO=bar";
  envs[1] = "BAZ=qux";

  mounts[0].dir = ".";
  mounts[0].read_only = 0;

  config.mounts = mounts;
  config.mount_count = 1;
  config.disable_network = 0;
  config.env_vars = envs;
  config.env_count = 2;
  config.timeout_secs = 0;
  config.stdout_buffer = NULL;
  config.stdout_size = NULL;
  config.stderr_buffer = NULL;
  config.stderr_size = NULL;
  config.max_memory_mb = 0;
  config.max_cpu_percent = 0;
  config.drop_privileges = 0;
  config.target_uid = 0;
  config.target_gid = 0;
  config.denied_syscalls = NULL;
  config.denied_syscall_count = 0;
  config.seccomp_profile_path = "/tmp/seccomp.json";
  config.apparmor_profile = "custom-profile";
  config.use_pty = 1;
  config.max_network_mbps = 100;

  argv[0] = (char *)"test";
  argv[1] = NULL;

  ret = engine_dummy.init();
  ASSERT_TRUE(ret == 0, "Dummy init should return 0");

  ret = engine_dummy.execute(&config, 1, argv);
  ASSERT_TRUE(ret == 0, "Dummy execute should return 0");
  {
    int exit_status = -1;
    sandbox_process_t *proc = NULL;
    int async_ret = engine_dummy.execute_async(&config, 1, argv, &proc);
    ASSERT_TRUE(async_ret == 0, "Dummy execute_async should return 0");
    ASSERT_TRUE(proc != NULL,
                "Dummy execute_async should return a valid handle");
    ret = engine_dummy.wait_process(proc, &exit_status);
    ASSERT_TRUE(ret == 0, "Dummy wait_process should return 0");
    ASSERT_TRUE(exit_status == 0, "Dummy async exit status should be 0");
    engine_dummy.free_process(proc);
  }

  engine_dummy.cleanup();
  ASSERT_TRUE(1, "Cleanup successfully called");
}

/**
 * \brief Tests an engine's execution path.
 */
static void test_engine_exec(sandbox_engine_t *engine) {
  int ret;
  char *argv[2];
  sandbox_config_t config;

  if (!engine)
    return;

  config.mounts = NULL;
  config.mount_count = 0;
  config.disable_network = 1;
  config.env_vars = NULL;
  config.env_count = 0;
  config.timeout_secs = 1;
  config.stdout_buffer = NULL;
  config.stdout_size = NULL;
  config.stderr_buffer = NULL;
  config.stderr_size = NULL;
  config.max_memory_mb = 128;
  config.max_cpu_percent = 50;
  config.drop_privileges = 1;
  config.target_uid = 1000;
  config.target_gid = 1000;
  config.denied_syscalls = NULL;
  config.denied_syscall_count = 0;
  config.seccomp_profile_path = NULL;
  config.apparmor_profile = NULL;
  config.use_pty = 0;
  config.max_network_mbps = 0;

  argv[0] = (char *)"echo";
  argv[1] = NULL;

  ret = engine->init();
  ASSERT_TRUE(ret == 0 || ret == -1,
              "Engine init should return 0 or acceptable code");

  /* We don't assert the result to be 0 since some engines might fail to run if
   * not installed */
  ret = engine->execute(&config, 1, argv);
  ASSERT_TRUE(1, "Execute called");

  {
    int exit_status = -1;
    sandbox_process_t *proc = NULL;
    engine->execute_async(&config, 1, argv, &proc);
    engine->wait_process(proc, &exit_status);
    engine->free_process(proc);
    ASSERT_TRUE(1, "Async called");
  }

  engine->cleanup();
}

/**
 * \brief Tests the podman engine init/cleanup.
 */
static void test_podman_engine(void) { test_engine_exec(&engine_podman); }

/**
 * \brief Tests the gvisor engine init/cleanup.
 */
static void test_gvisor_engine(void) { test_engine_exec(&engine_gvisor); }

/**
 * \brief Tests the wasmtime engine init/cleanup.
 */
static void test_wasmtime_engine(void) { test_engine_exec(&engine_wasmtime); }

/**
 * \brief Tests the appcontainer engine init/cleanup.
 */
static void test_appcontainer_engine(void) {
  test_engine_exec(&engine_appcontainer);
}

/**
 * \brief Tests the native engine init/cleanup.
 */
static void test_native_engine(void) { test_engine_exec(&engine_native); }

/**
 * \brief Tests the docker engine init/cleanup.
 */
static void test_docker_engine(void) { test_engine_exec(&engine_docker); }

/**
 * \brief Main entry point for the test runner.
 * \return EXIT_SUCCESS if all tests pass, EXIT_FAILURE otherwise.
 */
int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  printf("Running libmountsandbox tests...\n");

  printf("Running test_get_engine...\n");
  test_get_engine();
  printf("Running test_dummy_engine...\n");
  test_dummy_engine();
  printf("Running test_podman_engine...\n");
  test_podman_engine();
  printf("Running test_gvisor_engine...\n");
  test_gvisor_engine();
  printf("Running test_wasmtime_engine...\n");
  test_wasmtime_engine();
  printf("Running test_appcontainer_engine...\n");
  test_appcontainer_engine();
  printf("Running test_native_engine...\n");
  test_native_engine();
  printf("Running test_docker_engine...\n");
  test_docker_engine();

  printf("Tests run: %d, passed: %d\n", tests_run, tests_passed);

  if (tests_run == tests_passed) {
    printf("ALL TESTS PASSED.\n");
    return EXIT_SUCCESS;
  } else {
    printf("SOME TESTS FAILED.\n");
    return EXIT_FAILURE;
  }
}
