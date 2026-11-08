#if !defined(_WIN32) && !defined(__WATCOMC__)
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif
#endif
/**
 * @file test_sandbox.c
 * @brief C89-compliant unit tests for libmountsandbox using greatest.h and OOM
 * fault-injection mocking.
 */
/* clang-format off */
#include "greatest.h"
#include "sandbox.h"
#include "sandbox_common.h"
#include "log.h"
#include "../src/main.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* clang-format on */

/** @brief Countdown until malloc fails. */
extern int g_sandbox_mock_malloc_countdown;
/** @brief Countdown until tmpfile fails. */
extern int g_sandbox_mock_tmpfile_countdown;
/** @brief Simulated spawn behavior. */
extern int g_sandbox_mock_spawn_mode;
/** @brief Flag to force ftell to return -1. */
extern int g_sandbox_mock_ftell_neg;
/** @brief Flag to force fseek to fail. */
extern int g_sandbox_mock_fseek_fail;
/** @brief Flag to force log_debug to fail. */
extern int g_sandbox_mock_log_fail;

/**
 * @brief Resets all fault-injection globals to their default state.
 * @return SANDBOX_SUCCESS on completion.
 */
static sandbox_error_t reset_mocks(void) {
  g_sandbox_mock_malloc_countdown = 0;
  g_sandbox_mock_tmpfile_countdown = 0;
  g_sandbox_mock_spawn_mode = 0;
  g_sandbox_mock_ftell_neg = 0;
  g_sandbox_mock_fseek_fail = 0;
  g_sandbox_mock_log_fail = 0;
  return SANDBOX_SUCCESS;
}

/**
 * @brief Mock init function that fails with SANDBOX_ERR_EXEC_FAILED.
 * @return SANDBOX_ERR_EXEC_FAILED.
 */
static sandbox_error_t mock_fail_init(void) { return SANDBOX_ERR_EXEC_FAILED; }

/**
 * @brief Mock cleanup function that fails with SANDBOX_ERR_IO.
 * @return SANDBOX_ERR_IO.
 */
static sandbox_error_t mock_fail_cleanup(void) { return SANDBOX_ERR_IO; }

/**
 * @brief Tests engine retrieval and invalid argument handling in sandbox.c.
 * @return greatest_test_res result.
 */
TEST test_get_engine(void) {
  sandbox_engine_t *engine = NULL;
  sandbox_error_t rc;

  rc = get_sandbox_engine(NULL, NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);

  rc = get_sandbox_engine("dummy", NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);

  rc = get_sandbox_engine(NULL, &engine);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  ASSERT_EQ(NULL, engine);

  rc = get_sandbox_engine("dummy", &engine);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT(engine != NULL);
  ASSERT_STR_EQ("dummy", engine->engine_name);

  rc = get_sandbox_engine("docker", &engine);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT(engine != NULL);
  ASSERT_STR_EQ("docker", engine->engine_name);

  rc = get_sandbox_engine("podman", &engine);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT(engine != NULL);
  ASSERT_STR_EQ("podman", engine->engine_name);

  rc = get_sandbox_engine("gvisor", &engine);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT(engine != NULL);
  ASSERT_STR_EQ("gvisor", engine->engine_name);

  rc = get_sandbox_engine("wasmtime", &engine);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT(engine != NULL);
  ASSERT_STR_EQ("wasmtime", engine->engine_name);

  rc = get_sandbox_engine("appcontainer", &engine);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT(engine != NULL);
  ASSERT_STR_EQ("appcontainer", engine->engine_name);

  rc = get_sandbox_engine("native", &engine);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT(engine != NULL);
  ASSERT_STR_EQ("native", engine->engine_name);

  rc = get_sandbox_engine("non_existent_engine", &engine);
  ASSERT_EQ(SANDBOX_ERR_NOT_FOUND, rc);
  ASSERT_EQ(NULL, engine);

  PASS();
}

/**
 * @brief Tests libmountsandbox_log_debug in log.c.
 * @return greatest_test_res result.
 */
TEST test_logging(void) {
  sandbox_error_t rc;
  rc = libmountsandbox_log_debug(NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = libmountsandbox_log_debug("Test log message %d %s", 123, "ok");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  PASS();
}

/**
 * @brief Tests sandbox_common.c functions including tmpfile, buffer reading,
 * SBPL path escaping, Job Object limit calculation, OOM, and process spawning.
 * @return greatest_test_res result.
 */
TEST test_common_helpers(void) {
  sandbox_error_t rc;
  FILE *fp = NULL;
  char *buf = NULL;
  char *escaped = NULL;
  size_t sz = 0;
  sandbox_config_t cfg;
  sandbox_job_limits_t job_limits;
  char *argv[3];
  int status = -1;

  rc = reset_mocks();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  memset(&cfg, 0, sizeof(cfg));

  rc = sandbox_alloc(16, NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);

  rc = sandbox_open_tmpfile(NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);

  /* Test sandbox_escape_sbpl_path */
  rc = sandbox_escape_sbpl_path(NULL, &escaped);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = sandbox_escape_sbpl_path("/tmp", NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);

  {
    char special_path[8];
    special_path[0] = 47;
    special_path[1] = 97;
    special_path[2] = 34;
    special_path[3] = 92;
    special_path[4] = 98;
    special_path[5] = 0;

    g_sandbox_mock_malloc_countdown = 1;
    rc = sandbox_escape_sbpl_path(special_path, &escaped);
    ASSERT_EQ(SANDBOX_ERR_OUT_OF_MEMORY, rc);
    ASSERT_EQ(NULL, escaped);
    rc = reset_mocks();
    ASSERT_EQ(SANDBOX_SUCCESS, rc);

    rc = sandbox_escape_sbpl_path(special_path, &escaped);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    ASSERT(escaped != NULL);
    ASSERT_EQ(7u, (unsigned int)strlen(escaped));
    ASSERT_EQ(92, escaped[2]);
    ASSERT_EQ(34, escaped[3]);
    ASSERT_EQ(92, escaped[4]);
    ASSERT_EQ(92, escaped[5]);
    free(escaped);
    escaped = NULL;
  }

  /* Test sandbox_configure_job_limits */
  rc = sandbox_configure_job_limits(NULL, &job_limits);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = sandbox_configure_job_limits(&cfg, NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);

  rc = sandbox_configure_job_limits(&cfg, &job_limits);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT_EQ(64u, job_limits.active_process_limit);
  ASSERT_EQ(0UL, job_limits.process_memory_bytes);
  ASSERT_EQ(0u, job_limits.cpu_rate_percent);

  cfg.max_memory_mb = 64;
  cfg.max_cpu_percent = 50;
  rc = sandbox_configure_job_limits(&cfg, &job_limits);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT_EQ(64UL * 1024UL * 1024UL, job_limits.process_memory_bytes);
  ASSERT_EQ(50u, job_limits.cpu_rate_percent);

  cfg.max_cpu_percent = 250;
  rc = sandbox_configure_job_limits(&cfg, &job_limits);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT_EQ(100u, job_limits.cpu_rate_percent);
  memset(&cfg, 0, sizeof(cfg));

  g_sandbox_mock_tmpfile_countdown = 1;
  rc = sandbox_open_tmpfile(&fp);
  ASSERT_EQ(SANDBOX_ERR_IO, rc);
  ASSERT_EQ(NULL, fp);
  rc = reset_mocks();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  rc = sandbox_open_tmpfile(&fp);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT(fp != NULL);
  fputs("hello_stream", fp);
  fflush(fp);

  rc = sandbox_read_fp_to_buffer(NULL, &buf, &sz);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = sandbox_read_fp_to_buffer(fp, NULL, &sz);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);

  g_sandbox_mock_fseek_fail = 1;
  rc = sandbox_read_fp_to_buffer(fp, &buf, &sz);
  ASSERT_EQ(SANDBOX_ERR_IO, rc);
  rc = reset_mocks();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  g_sandbox_mock_malloc_countdown = 1;
  rc = sandbox_read_fp_to_buffer(fp, &buf, &sz);
  ASSERT_EQ(SANDBOX_ERR_OUT_OF_MEMORY, rc);
  ASSERT_EQ(0u, sz);
  g_sandbox_mock_malloc_countdown = 1;
  rc = sandbox_read_fp_to_buffer(fp, &buf, NULL);
  ASSERT_EQ(SANDBOX_ERR_OUT_OF_MEMORY, rc);
  rc = reset_mocks();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  g_sandbox_mock_ftell_neg = 1;
  rc = sandbox_read_fp_to_buffer(fp, &buf, NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT(buf != NULL);
  free(buf);
  buf = NULL;
  rc = reset_mocks();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  rc = sandbox_read_fp_to_buffer(fp, &buf, &sz);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT(buf != NULL);
  ASSERT_STR_EQ("hello_stream", buf);
  ASSERT_EQ(12u, sz);
  free(buf);
  fclose(fp);

  argv[0] = (char *)"echo";
  argv[1] = (char *)"test";
  argv[2] = NULL;

  rc = sandbox_spawn_and_wait(NULL, argv, &cfg, NULL, NULL, &status);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = sandbox_spawn_and_wait("echo", NULL, &cfg, NULL, NULL, &status);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = sandbox_spawn_and_wait("echo", argv, NULL, NULL, NULL, &status);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = sandbox_spawn_and_wait("echo", argv, &cfg, NULL, NULL, NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);

  /* Spawn with stream capture */
  cfg.timeout_secs = 2;
  {
    FILE *out_fp = NULL;
    FILE *err_fp = NULL;
    rc = sandbox_open_tmpfile(&out_fp);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    rc = sandbox_open_tmpfile(&err_fp);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    rc = sandbox_spawn_and_wait("echo", argv, &cfg, out_fp, err_fp, &status);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    fclose(out_fp);
    fclose(err_fp);
  }

  /* Mock spawn modes */
  g_sandbox_mock_spawn_mode = 1;
  rc = sandbox_spawn_and_wait("echo", argv, &cfg, NULL, NULL, &status);
  ASSERT_EQ(SANDBOX_ERR_EXEC_FAILED, rc);

  g_sandbox_mock_log_fail = 1;
  rc = sandbox_spawn_and_wait("echo", argv, &cfg, NULL, NULL, &status);
  ASSERT_EQ(SANDBOX_ERR_IO, rc);
  g_sandbox_mock_log_fail = 0;

  g_sandbox_mock_spawn_mode = 2;
  rc = sandbox_spawn_and_wait("echo", argv, &cfg, NULL, NULL, &status);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT_EQ(124, status);

  g_sandbox_mock_spawn_mode = 4;
  rc = sandbox_spawn_and_wait("echo", argv, &cfg, NULL, NULL, &status);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT_EQ(42, status);

  g_sandbox_mock_spawn_mode = 5;
  rc = sandbox_spawn_and_wait("echo", argv, &cfg, NULL, NULL, &status);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT_EQ(-5, status);

  rc = reset_mocks();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  PASS();
}

/**
 * @brief Tests dummy engine sync, async, wait, free, cleanup, and OOM paths.
 * @return greatest_test_res result.
 */
TEST test_dummy_engine(void) {
  sandbox_engine_t *engine = NULL;
  sandbox_config_t cfg;
  char *argv[2];
  int status = -1;
  sandbox_process_t *proc = NULL;
  sandbox_error_t rc;

  rc = reset_mocks();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  memset(&cfg, 0, sizeof(cfg));
  argv[0] = (char *)"echo";
  argv[1] = NULL;

  rc = get_sandbox_engine("dummy", &engine);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  rc = engine->init();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  rc = engine->execute(NULL, 1, argv, &status);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = engine->execute(&cfg, -1, argv, &status);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = engine->execute(&cfg, 1, NULL, &status);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);

  rc = engine->execute(&cfg, 1, argv, NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = engine->execute(&cfg, 1, argv, &status);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT_EQ(0, status);

  rc = engine->execute_async(NULL, 1, argv, &proc);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = engine->execute_async(&cfg, -1, argv, &proc);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = engine->execute_async(&cfg, 1, NULL, &proc);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = engine->execute_async(&cfg, 1, argv, NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);

  g_sandbox_mock_malloc_countdown = 1;
  rc = engine->execute_async(&cfg, 1, argv, &proc);
  ASSERT_EQ(SANDBOX_ERR_OUT_OF_MEMORY, rc);
  ASSERT_EQ(NULL, proc);
  rc = reset_mocks();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  rc = engine->execute_async(&cfg, 1, argv, &proc);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT(proc != NULL);

  rc = engine->wait_process(NULL, &status);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = engine->wait_process(proc, NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);

  rc = engine->wait_process(proc, &status);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT_EQ(0, status);

  rc = engine->free_process(NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = engine->free_process(proc);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  rc = engine->cleanup();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  PASS();
}

/**
 * @brief Tests docker, podman, and gvisor engines across all configuration
 * branches and OOM points.
 * @return greatest_test_res result.
 */
TEST test_container_engines(void) {
  const char *names[3];
  int idx;

  names[0] = "docker";
  names[1] = "podman";
  names[2] = "gvisor";

  for (idx = 0; idx < 3; idx++) {
    sandbox_engine_t *engine = NULL;
    sandbox_config_t cfg;
    sandbox_mount_t mounts[2];
    const char *envs[1];
    const char *syscalls[1];
    char *argv[2];
    int status = -1;
    char *out_buf = NULL;
    size_t out_sz = 0;
    char *err_buf = NULL;
    size_t err_sz = 0;
    sandbox_process_t *proc = NULL;
    sandbox_error_t rc;
    int oom_step;

    rc = reset_mocks();
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    rc = get_sandbox_engine(names[idx], &engine);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    ASSERT(engine != NULL);

    rc = engine->init();
    ASSERT_EQ(SANDBOX_SUCCESS, rc);

    argv[0] = (char *)"echo";
    argv[1] = NULL;

    /* Invalid arguments */
    memset(&cfg, 0, sizeof(cfg));
    rc = engine->execute(NULL, 1, argv, &status);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = engine->execute(&cfg, -1, argv, &status);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = engine->execute(&cfg, 1, NULL, &status);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);

    /* Minimal execution */
    g_sandbox_mock_spawn_mode = 3;
    rc = engine->execute(&cfg, 1, argv, &status);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    cfg.apparmor_profile = "only-apparmor";
    rc = engine->execute(&cfg, 1, argv, NULL);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    ASSERT_EQ(0, status);

    /* Drop privileges with default UID/GID (0:0 -> 65534:65534) and 0:1000 */
    cfg.drop_privileges = 1;
    rc = engine->execute(&cfg, 1, argv, NULL);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    cfg.target_gid = 1000;
    rc = engine->execute(&cfg, 1, argv, NULL);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    cfg.target_gid = 0;

    /* Full configuration with custom UID/GID, mounts, envs, syscalls, profiles
     */
    mounts[0].dir = "/tmp";
    mounts[0].read_only = 0;
    mounts[1].dir = "/var";
    mounts[1].read_only = 1;
    envs[0] = "FOO=BAR";
    syscalls[0] = "ptrace";

    cfg.mounts = mounts;
    cfg.mount_count = 2;
    cfg.disable_network = 1;
    cfg.env_vars = envs;
    cfg.env_count = 1;
    cfg.timeout_secs = 5;
    cfg.stdout_buffer = &out_buf;
    cfg.stdout_size = &out_sz;
    cfg.stderr_buffer = &err_buf;
    cfg.stderr_size = &err_sz;
    cfg.max_memory_mb = 128;
    cfg.max_cpu_percent = 150;
    cfg.drop_privileges = 1;
    cfg.target_uid = 1000;
    cfg.target_gid = 1000;
    cfg.denied_syscalls = syscalls;
    cfg.denied_syscall_count = 1;
    cfg.seccomp_profile_path = "/etc/seccomp.json";
    cfg.apparmor_profile = "docker-default";
    cfg.use_pty = 1;
    cfg.max_network_mbps = 10;

    rc = engine->execute(&cfg, 1, argv, &status);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    if (out_buf) {
      free(out_buf);
      out_buf = NULL;
    }
    if (err_buf) {
      free(err_buf);
      err_buf = NULL;
    }

    /* Test tmpfile failure on stdout (1st call) and stderr (2nd call) */
    g_sandbox_mock_tmpfile_countdown = 1;
    rc = engine->execute(&cfg, 1, argv, &status);
    ASSERT_EQ(SANDBOX_ERR_IO, rc);
    g_sandbox_mock_tmpfile_countdown = 2;
    rc = engine->execute(&cfg, 1, argv, &status);
    ASSERT_EQ(SANDBOX_ERR_IO, rc);
    rc = reset_mocks();
    ASSERT_EQ(SANDBOX_SUCCESS, rc);

    g_sandbox_mock_spawn_mode = 1;
    rc = engine->execute(&cfg, 1, argv, &status);
    ASSERT_EQ(SANDBOX_ERR_EXEC_FAILED, rc);
    rc = reset_mocks();
    ASSERT_EQ(SANDBOX_SUCCESS, rc);

    /* Test every OOM point during full execution */
    for (oom_step = 1; oom_step <= 8; oom_step++) {
      out_buf = NULL;
      err_buf = NULL;
      g_sandbox_mock_spawn_mode = 3;
      g_sandbox_mock_malloc_countdown = oom_step;
      rc = engine->execute(&cfg, 1, argv, &status);
      if (out_buf) {
        free(out_buf);
        out_buf = NULL;
      }
      ASSERT_EQ(SANDBOX_ERR_OUT_OF_MEMORY, rc);
    }
    rc = reset_mocks();
    ASSERT_EQ(SANDBOX_SUCCESS, rc);

    /* Async, wait, free, cleanup */
    rc = engine->execute_async(NULL, 1, argv, &proc);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = engine->execute_async(&cfg, -1, argv, &proc);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = engine->execute_async(&cfg, 1, NULL, &proc);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = engine->execute_async(&cfg, 1, argv, NULL);
    ASSERT_EQ(SANDBOX_ERR_UNSUPPORTED, rc);
    rc = engine->execute_async(&cfg, 1, argv, &proc);
    ASSERT_EQ(SANDBOX_ERR_UNSUPPORTED, rc);

    rc = engine->wait_process(NULL, &status);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = engine->wait_process((sandbox_process_t *)&status, NULL);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = engine->wait_process((sandbox_process_t *)&status, &status);
    ASSERT_EQ(SANDBOX_ERR_UNSUPPORTED, rc);

    rc = engine->free_process(NULL);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    {
      void *dummy_proc = malloc(4);
      rc = engine->free_process((sandbox_process_t *)dummy_proc);
      ASSERT_EQ(SANDBOX_SUCCESS, rc);
    }

    rc = engine->cleanup();
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
  }
  PASS();
}

/**
 * @brief Tests wasmtime engine across all configuration and OOM branches.
 * @return greatest_test_res result.
 */
TEST test_wasmtime_engine(void) {
  sandbox_engine_t *engine = NULL;
  sandbox_config_t cfg;
  sandbox_mount_t mounts[2];
  const char *envs[1];
  const char *syscalls[1];
  char *argv[2];
  int status = -1;
  char *out_buf = NULL;
  size_t out_sz = 0;
  char *err_buf = NULL;
  size_t err_sz = 0;
  sandbox_process_t *proc = NULL;
  sandbox_error_t rc;
  int oom_step;

  rc = reset_mocks();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = get_sandbox_engine("wasmtime", &engine);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  rc = engine->init();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  argv[0] = (char *)"app.wasm";
  argv[1] = NULL;

  memset(&cfg, 0, sizeof(cfg));
  rc = engine->execute(NULL, 1, argv, &status);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = engine->execute(&cfg, 0, argv, &status);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = engine->execute(&cfg, 1, NULL, &status);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);

  g_sandbox_mock_spawn_mode = 3;
  rc = engine->execute(&cfg, 1, argv, &status);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = engine->execute(&cfg, 1, argv, NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  g_sandbox_mock_spawn_mode = 1;
  rc = engine->execute(&cfg, 1, argv, &status);
  ASSERT_EQ(SANDBOX_ERR_EXEC_FAILED, rc);
  g_sandbox_mock_spawn_mode = 3;

  mounts[0].dir = "/tmp";
  mounts[0].read_only = 0;
  mounts[1].dir = "/var";
  mounts[1].read_only = 1;
  envs[0] = "WASI_ENV=1";
  syscalls[0] = "clock_time_get";

  cfg.mounts = mounts;
  cfg.mount_count = 2;
  cfg.disable_network = 1;
  cfg.env_vars = envs;
  cfg.env_count = 1;
  cfg.stdout_buffer = &out_buf;
  cfg.stdout_size = &out_sz;
  cfg.stderr_buffer = &err_buf;
  cfg.stderr_size = &err_sz;
  cfg.max_memory_mb = 64;
  cfg.max_cpu_percent = 50;
  cfg.drop_privileges = 1;
  cfg.denied_syscalls = syscalls;
  cfg.denied_syscall_count = 1;

  rc = engine->execute(&cfg, 1, argv, &status);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  if (out_buf) {
    free(out_buf);
    out_buf = NULL;
  }
  if (err_buf) {
    free(err_buf);
    err_buf = NULL;
  }

  g_sandbox_mock_tmpfile_countdown = 1;
  rc = engine->execute(&cfg, 1, argv, &status);
  ASSERT_EQ(SANDBOX_ERR_IO, rc);
  g_sandbox_mock_tmpfile_countdown = 2;
  rc = engine->execute(&cfg, 1, argv, &status);
  ASSERT_EQ(SANDBOX_ERR_IO, rc);
  rc = reset_mocks();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  for (oom_step = 1; oom_step <= 6; oom_step++) {
    out_buf = NULL;
    err_buf = NULL;
    g_sandbox_mock_spawn_mode = 3;
    g_sandbox_mock_malloc_countdown = oom_step;
    rc = engine->execute(&cfg, 1, argv, &status);
    if (out_buf) {
      free(out_buf);
      out_buf = NULL;
    }
    ASSERT_EQ(SANDBOX_ERR_OUT_OF_MEMORY, rc);
  }
  rc = reset_mocks();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  rc = engine->execute_async(NULL, 1, argv, &proc);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = engine->execute_async(&cfg, -1, argv, &proc);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = engine->execute_async(&cfg, 1, NULL, &proc);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = engine->execute_async(&cfg, 1, argv, NULL);
  ASSERT_EQ(SANDBOX_ERR_UNSUPPORTED, rc);
  rc = engine->execute_async(&cfg, 1, argv, &proc);
  ASSERT_EQ(SANDBOX_ERR_UNSUPPORTED, rc);

  rc = engine->wait_process(NULL, &status);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = engine->wait_process((sandbox_process_t *)&status, NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = engine->wait_process((sandbox_process_t *)&status, &status);
  ASSERT_EQ(SANDBOX_ERR_UNSUPPORTED, rc);

  rc = engine->free_process(NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  {
    void *dummy_proc = malloc(4);
    rc = engine->free_process((sandbox_process_t *)dummy_proc);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
  }

  rc = engine->cleanup();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  PASS();
}

/**
 * @brief Tests appcontainer and native engines across all configuration and
 * OOM branches.
 * @return greatest_test_res result.
 */
TEST test_appcontainer_and_native_engines(void) {
  const char *names[2];
  int idx;

  names[0] = "appcontainer";
  names[1] = "native";

  for (idx = 0; idx < 2; idx++) {
    sandbox_engine_t *engine = NULL;
    sandbox_config_t cfg;
    sandbox_mount_t mounts[2];
    const char *syscalls[1];
    char *argv[2];
    int status = -1;
    char *out_buf = NULL;
    size_t out_sz = 0;
    char *err_buf = NULL;
    size_t err_sz = 0;
    sandbox_process_t *proc = NULL;
    sandbox_error_t rc;
    int oom_step;

    rc = reset_mocks();
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    rc = get_sandbox_engine(names[idx], &engine);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);

    rc = engine->init();
    ASSERT_EQ(SANDBOX_SUCCESS, rc);

    argv[0] = (char *)"echo";
    argv[1] = NULL;

    memset(&cfg, 0, sizeof(cfg));
    rc = engine->execute(NULL, 1, argv, &status);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = engine->execute(&cfg, 0, argv, &status);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = engine->execute(&cfg, 1, NULL, &status);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);

    g_sandbox_mock_spawn_mode = 3;
    rc = engine->execute(&cfg, 1, argv, &status);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    cfg.apparmor_profile = "only-apparmor";
    rc = engine->execute(&cfg, 1, argv, NULL);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);

    mounts[0].dir = "/tmp";
    mounts[0].read_only = 0;
    mounts[1].dir = "/var";
    mounts[1].read_only = 1;
    syscalls[0] = "ptrace";

    cfg.mounts = mounts;
    cfg.mount_count = 2;
    cfg.disable_network = 1;
    cfg.stdout_buffer = &out_buf;
    cfg.stdout_size = &out_sz;
    cfg.stderr_buffer = &err_buf;
    cfg.stderr_size = &err_sz;
    cfg.max_memory_mb = 64;
    cfg.max_cpu_percent = 50;
    cfg.drop_privileges = 1;
    cfg.target_uid = 1000;
    cfg.target_gid = 1000;
    cfg.denied_syscalls = syscalls;
    cfg.denied_syscall_count = 1;
    cfg.seccomp_profile_path = "/etc/seccomp.json";
    cfg.apparmor_profile = "default";
    cfg.use_pty = 1;
    cfg.max_network_mbps = 10;

    rc = engine->execute(&cfg, 1, argv, &status);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    if (out_buf) {
      free(out_buf);
      out_buf = NULL;
    }
    if (err_buf) {
      free(err_buf);
      err_buf = NULL;
    }

    g_sandbox_mock_tmpfile_countdown = 1;
    rc = engine->execute(&cfg, 1, argv, &status);
    ASSERT_EQ(SANDBOX_ERR_IO, rc);
    g_sandbox_mock_tmpfile_countdown = 2;
    rc = engine->execute(&cfg, 1, argv, &status);
    ASSERT_EQ(SANDBOX_ERR_IO, rc);
    rc = reset_mocks();
    ASSERT_EQ(SANDBOX_SUCCESS, rc);

    g_sandbox_mock_spawn_mode = 1;
    rc = engine->execute(&cfg, 1, argv, &status);
    ASSERT_EQ(SANDBOX_ERR_EXEC_FAILED, rc);
    rc = reset_mocks();
    ASSERT_EQ(SANDBOX_SUCCESS, rc);

    {
      int max_oom = (idx == 0) ? 4 : 7;
      for (oom_step = 1; oom_step <= max_oom; oom_step++) {
        out_buf = NULL;
        err_buf = NULL;
        g_sandbox_mock_spawn_mode = 3;
        g_sandbox_mock_malloc_countdown = oom_step;
        rc = engine->execute(&cfg, 1, argv, &status);
        if (out_buf) {
          free(out_buf);
          out_buf = NULL;
        }
        ASSERT_EQ(SANDBOX_ERR_OUT_OF_MEMORY, rc);
      }
    }
    rc = reset_mocks();
    ASSERT_EQ(SANDBOX_SUCCESS, rc);

    rc = engine->execute_async(NULL, 1, argv, &proc);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = engine->execute_async(&cfg, -1, argv, &proc);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = engine->execute_async(&cfg, 1, NULL, &proc);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = engine->execute_async(&cfg, 1, argv, NULL);
    ASSERT_EQ(SANDBOX_ERR_UNSUPPORTED, rc);
    rc = engine->execute_async(&cfg, 1, argv, &proc);
    ASSERT_EQ(SANDBOX_ERR_UNSUPPORTED, rc);

    rc = engine->wait_process(NULL, &status);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = engine->wait_process((sandbox_process_t *)&status, NULL);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = engine->wait_process((sandbox_process_t *)&status, &status);
    ASSERT_EQ(SANDBOX_ERR_UNSUPPORTED, rc);

    rc = engine->free_process(NULL);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    {
      void *dummy_proc = malloc(4);
      rc = engine->free_process((sandbox_process_t *)dummy_proc);
      ASSERT_EQ(SANDBOX_SUCCESS, rc);
    }

    rc = engine->cleanup();
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
  }

  PASS();
}

/**
 * @brief Helper to set an environment variable across POSIX and Windows.
 * @param name Variable name.
 * @param value Variable value (or NULL/empty to clear).
 * @return SANDBOX_SUCCESS on completion.
 */
static sandbox_error_t set_test_env(const char *name, const char *value) {
#if defined(_MSC_VER)
  _putenv_s(name, value ? value : "");
#elif defined(_WIN32)
  {
    char buf[256];
    sprintf(buf, "%s=%s", name, value ? value : "");
    _putenv(buf);
  }
#else
  if (value) {
    setenv(name, value, 1);
  } else {
    unsetenv(name);
  }
#endif
  return SANDBOX_SUCCESS;
}

/**
 * @brief Tests CLI helpers and sandbox_cli_run in main.c.
 * @return greatest_test_res result.
 */
TEST test_cli_runner(void) {
  sandbox_error_t rc;
  int exit_code = 0;
  const char *val = NULL;
  int cnt = 0;
  char *dup_s = NULL;
  const char *arr[4];
  sandbox_mount_t m_arr[4];
  size_t count = 0;
  char *copy = NULL;
  int oom_step;

  rc = reset_mocks();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  /* Direct helper edge cases */
  rc = print_usage(NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = safe_getenv(NULL, &val);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = safe_getenv("PATH", NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = count_char(NULL, ',', &cnt);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT_EQ(0, cnt);
  rc = count_char("a,b", ',', NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = count_char("a,b,c", ',', &cnt);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT_EQ(2, cnt);

  rc = my_strdup(NULL, &dup_s);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = my_strdup("hi", NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  g_sandbox_mock_malloc_countdown = 1;
  rc = my_strdup("hi", &dup_s);
  ASSERT_EQ(SANDBOX_ERR_OUT_OF_MEMORY, rc);
  rc = reset_mocks();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  rc = split_and_append("a,b", ',', NULL, &count, &copy);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = split_and_append("a,b", ',', arr, NULL, &copy);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = split_and_append("a,b", ',', arr, &count, NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  g_sandbox_mock_malloc_countdown = 1;
  rc = split_and_append("a,b", ',', arr, &count, &copy);
  ASSERT_EQ(SANDBOX_ERR_OUT_OF_MEMORY, rc);
  rc = reset_mocks();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = split_and_append("a,b,", ',', arr, &count, &copy);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT_EQ(2u, count);
  free(copy);
  count = 0;
  rc = split_and_append("a,b", ',', arr, &count, &copy);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT_EQ(2u, count);
  free(copy);
  count = 0;

  rc = split_and_append_mount("a,b", ',', 1, NULL, &count, &copy);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = split_and_append_mount("a,b", ',', 1, m_arr, NULL, &copy);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  rc = split_and_append_mount("a,b", ',', 1, m_arr, &count, NULL);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  g_sandbox_mock_malloc_countdown = 1;
  rc = split_and_append_mount("a,b", ',', 1, m_arr, &count, &copy);
  ASSERT_EQ(SANDBOX_ERR_OUT_OF_MEMORY, rc);
  rc = reset_mocks();
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = split_and_append_mount("/a,/b,", ',', 1, m_arr, &count, &copy);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT_EQ(2u, count);
  free(copy);
  count = 0;
  rc = split_and_append_mount("/a,/b", ',', 1, m_arr, &count, &copy);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  ASSERT_EQ(2u, count);
  free(copy);

  /* CLI argument parsing tests */
  rc = sandbox_cli_run(1, NULL, &exit_code);
  ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  {
    char *args_tmp[] = {(char *)"mountsandbox", NULL};
    rc = sandbox_cli_run(1, args_tmp, NULL);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  }
  {
    char *args_only_flags[] = {(char *)"mountsandbox", (char *)"--no-network",
                               NULL};
    rc = sandbox_cli_run(2, args_only_flags, &exit_code);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  }

  {
    char *args1[] = {(char *)"mountsandbox", NULL};
    rc = sandbox_cli_run(1, args1, &exit_code);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = sandbox_cli_run(0, args1, &exit_code);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    g_sandbox_mock_getenv_fail = 1;
    {
      char *args2[] = {(char *)"mountsandbox", (char *)"echo", NULL};
      rc = sandbox_cli_run(2, args2, &exit_code);
      ASSERT_EQ(SANDBOX_ERR_IO, rc);
    }
    g_sandbox_mock_getenv_fail = 0;
  }
  {
    char *args_help[] = {(char *)"mountsandbox", (char *)"--help", NULL};
    char *args_help_null[] = {NULL, (char *)"--help", NULL};
    rc = sandbox_cli_run(2, args_help, &exit_code);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    ASSERT_EQ(EXIT_SUCCESS, exit_code);
    rc = sandbox_cli_run(2, args_help_null, &exit_code);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  }
  {
    char *args_ver[] = {(char *)"mountsandbox", (char *)"--version", NULL};
    rc = sandbox_cli_run(2, args_ver, &exit_code);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    ASSERT_EQ(EXIT_SUCCESS, exit_code);
    g_sandbox_mock_print_version_fail = 1;
    rc = sandbox_cli_run(2, args_ver, &exit_code);
    ASSERT_EQ(SANDBOX_ERR_IO, rc);
    g_sandbox_mock_print_version_fail = 0;
  }
  {
    char *args_unk[] = {(char *)"mountsandbox", (char *)"--bad-flag", NULL};
    char *args_unk_null[] = {NULL, (char *)"--bad-flag", NULL};
    rc = sandbox_cli_run(2, args_unk, &exit_code);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = sandbox_cli_run(2, args_unk_null, &exit_code);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  }
  {
    char *args_nocmd[] = {(char *)"mountsandbox", (char *)"--", NULL};
    char *args_nocmd_null[] = {NULL, (char *)"--", NULL};
    rc = sandbox_cli_run(2, args_nocmd, &exit_code);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    rc = sandbox_cli_run(2, args_nocmd_null, &exit_code);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
  }
  {
    char *args_badeng[] = {(char *)"mountsandbox", (char *)"--engine=invalid",
                           (char *)"--", (char *)"echo", NULL};
    rc = sandbox_cli_run(4, args_badeng, &exit_code);
    ASSERT_EQ(SANDBOX_ERR_NOT_FOUND, rc);
  }
  {
    char *args_all[] = {(char *)"mountsandbox",
                        (char *)"--engine=dummy",
                        (char *)"--no-network",
                        (char *)"--env=K=V",
                        (char *)"--mount=/tmp",
                        (char *)"--ro-mount=/var",
                        (char *)"--timeout=5",
                        (char *)"--memory-mb=64",
                        (char *)"--cpu-pct=50",
                        (char *)"--drop-privs",
                        (char *)"--uid=1000",
                        (char *)"--gid=1000",
                        (char *)"--deny-syscall=ptrace",
                        (char *)"--",
                        (char *)"echo",
                        (char *)"hi",
                        NULL};
    rc = sandbox_cli_run(16, args_all, &exit_code);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    ASSERT_EQ(EXIT_SUCCESS, exit_code);

    for (oom_step = 1; oom_step <= 3; oom_step++) {
      g_sandbox_mock_malloc_countdown = oom_step;
      rc = sandbox_cli_run(16, args_all, &exit_code);
      ASSERT_EQ(SANDBOX_ERR_OUT_OF_MEMORY, rc);
    }
    rc = reset_mocks();
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
  }

  /* Environment variable configuration and OOM paths in sandbox_cli_run */
  rc = set_test_env("MOUNTSANDBOX_ENGINE", "dummy");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_NO_NETWORK", "1");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_ENV", "E1=V1,E2=V2");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_MOUNT", "/m1,/m2");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_RO_MOUNT", "/ro1,/ro2");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_TIMEOUT", "10");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_MEMORY_MB", "128");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_CPU_PCT", "80");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_DROP_PRIVS", "1");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_UID", "1001");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_GID", "1001");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_DENY_SYSCALL", "ptrace,mount");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  {
    char *args_env[] = {(char *)"mountsandbox", (char *)"echo", NULL};
    g_sandbox_mock_count_char_fail = 1;
    rc = sandbox_cli_run(2, args_env, &exit_code);
    ASSERT_EQ(SANDBOX_ERR_INVALID_ARG, rc);
    g_sandbox_mock_count_char_fail = 0;
    for (oom_step = 1; oom_step <= 7; oom_step++) {
      g_sandbox_mock_malloc_countdown = oom_step;
      rc = sandbox_cli_run(2, args_env, &exit_code);
      ASSERT_EQ(SANDBOX_ERR_OUT_OF_MEMORY, rc);
    }
    rc = reset_mocks();
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    rc = sandbox_cli_run(2, args_env, &exit_code);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
  }

  rc = set_test_env("MOUNTSANDBOX_NO_NETWORK", "0");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_DROP_PRIVS", "0");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  {
    char *args_env0[] = {(char *)"mountsandbox", (char *)"echo", NULL};
    rc = sandbox_cli_run(2, args_env0, &exit_code);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
  }
  rc = set_test_env("MOUNTSANDBOX_NO_NETWORK", "false");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_DROP_PRIVS", "false");
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  {
    char *args_envf[] = {(char *)"mountsandbox", (char *)"echo", NULL};
    rc = sandbox_cli_run(2, args_envf, &exit_code);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
  }
  rc = set_test_env("MOUNTSANDBOX_ENGINE", NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_NO_NETWORK", NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_ENV", NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_MOUNT", NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_RO_MOUNT", NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_TIMEOUT", NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_MEMORY_MB", NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_CPU_PCT", NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_DROP_PRIVS", NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_UID", NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_GID", NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);
  rc = set_test_env("MOUNTSANDBOX_DENY_SYSCALL", NULL);
  ASSERT_EQ(SANDBOX_SUCCESS, rc);

  {
    char *args_nomount[] = {(char *)"mountsandbox", (char *)"--engine=docker",
                            (char *)"--", (char *)"echo", NULL};
    g_sandbox_mock_spawn_mode = 4;
    rc = sandbox_cli_run(4, args_nomount, &exit_code);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    ASSERT_EQ(42, exit_code);

    g_sandbox_mock_spawn_mode = 5;
    rc = sandbox_cli_run(4, args_nomount, &exit_code);
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
    ASSERT_EQ(EXIT_FAILURE, exit_code);

    g_sandbox_mock_spawn_mode = 1;
    rc = sandbox_cli_run(4, args_nomount, &exit_code);
    ASSERT_EQ(SANDBOX_ERR_EXEC_FAILED, rc);
    rc = reset_mocks();
    ASSERT_EQ(SANDBOX_SUCCESS, rc);
  }

  /* Test engine init and cleanup failure handling in sandbox_cli_run */
  {
    sandbox_error_t (*orig_init)(void) = engine_dummy.init;
    sandbox_error_t (*orig_cleanup)(void) = engine_dummy.cleanup;
    char *args_dummy[] = {(char *)"mountsandbox", (char *)"--engine=dummy",
                          (char *)"--", (char *)"echo", NULL};

    engine_dummy.init = mock_fail_init;
    rc = sandbox_cli_run(4, args_dummy, &exit_code);
    ASSERT_EQ(SANDBOX_ERR_EXEC_FAILED, rc);
    engine_dummy.init = orig_init;

    engine_dummy.cleanup = mock_fail_cleanup;
    rc = sandbox_cli_run(4, args_dummy, &exit_code);
    ASSERT_EQ(SANDBOX_ERR_IO, rc);
    engine_dummy.cleanup = orig_cleanup;
  }

  PASS();
}

/**
 * @brief Registers the sandbox unit test suite.
 */
SUITE(sandbox_suite) {
  RUN_TEST(test_get_engine);
  RUN_TEST(test_logging);
  RUN_TEST(test_common_helpers);
  RUN_TEST(test_dummy_engine);
  RUN_TEST(test_container_engines);
  RUN_TEST(test_wasmtime_engine);
  RUN_TEST(test_appcontainer_and_native_engines);
  RUN_TEST(test_cli_runner);
}

/** @brief Expands greatest test runner state definitions. */
GREATEST_MAIN_DEFS();

/**
 * @brief Entry point for the unit test executable.
 * @param argc Argument count.
 * @param argv Argument vector.
 * @return Test suite exit code.
 */
int main(int argc, char **argv) {
  GREATEST_MAIN_BEGIN();
  RUN_SUITE(sandbox_suite);
  GREATEST_MAIN_END();
}
