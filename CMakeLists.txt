cmake_minimum_required(VERSION 3.10)
project(libmountsandbox VERSION 0.1.0 LANGUAGES C)

# Enforce strictly C89 standard
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Define source files for the sandbox core library
set(SANDBOX_SOURCES
    src/sandbox.c
    src/engine_dummy.c
    src/engine_docker.c
    src/engine_podman.c
    src/engine_gvisor.c
    src/engine_wasmtime.c
    src/engine_appcontainer.c
    src/engine_native.c
)

include(FetchContent)
FetchContent_Declare(
    c_fs
    URL https://github.com/SamuelMarks/c-fs/archive/refs/heads/master.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(c_fs)

# Create static library for reusability across main and tests
add_library(sandbox_lib STATIC ${SANDBOX_SOURCES})
set_target_properties(sandbox_lib PROPERTIES OUTPUT_NAME "mountsandbox_static")
target_link_libraries(sandbox_lib PRIVATE cfs)

# Create shared library for FFI bindings
add_library(sandbox_lib_shared SHARED ${SANDBOX_SOURCES})
set_target_properties(sandbox_lib_shared PROPERTIES OUTPUT_NAME "mountsandbox")
target_link_libraries(sandbox_lib_shared PRIVATE cfs)

# Add main executable
add_executable(mountsandbox src/main.c)
target_link_libraries(mountsandbox PRIVATE sandbox_lib)

# Enable strict warnings for GCC/Clang to ensure C89 compliance
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    set(STRICT_C89_FLAGS "-Wall" "-Wextra" "-pedantic" "-Wmissing-prototypes" "-Wstrict-prototypes")
    target_compile_options(sandbox_lib PRIVATE ${STRICT_C89_FLAGS})
    target_compile_options(mountsandbox PRIVATE ${STRICT_C89_FLAGS})
endif()

# Setup testing framework
enable_testing()

add_executable(test_sandbox tests/test_sandbox.c)
target_link_libraries(test_sandbox PRIVATE sandbox_lib)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(test_sandbox PRIVATE ${STRICT_C89_FLAGS})
endif()

add_test(NAME test_sandbox COMMAND test_sandbox)
add_test(NAME test_cli_help COMMAND mountsandbox --help)
add_test(NAME test_cli_version COMMAND mountsandbox --version)
add_test(NAME test_cli_dummy COMMAND mountsandbox --engine=dummy -- echo hello)
