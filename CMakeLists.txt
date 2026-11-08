cmake_minimum_required(VERSION 3.10)
cmake_policy(SET CMP0091 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0091 NEW)
if(POLICY CMP0077)
    cmake_policy(SET CMP0077 NEW)
endif()
if(POLICY CMP0141)
    cmake_policy(SET CMP0141 NEW)
    set(CMAKE_POLICY_DEFAULT_CMP0141 NEW)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Windows" AND CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
    set(CMAKE_OSX_ARCHITECTURES "")
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
endif()

project(libmountsandbox VERSION 0.1.0 LANGUAGES C)

if(MSVC)
    if(CMAKE_C_FLAGS MATCHES "/W[0-4]")
        string(REGEX REPLACE "/W[0-4]" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
    endif()
    if(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT STREQUAL "Embedded" OR CMAKE_CROSSCOMPILING)
        string(REPLACE "/Zi" "/Z7" CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG}")
        string(REPLACE "/Zi" "/Z7" CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO}")
        string(REPLACE "/Fd<TARGET_COMPILE_PDB>" "" CMAKE_C_COMPILE_OBJECT "${CMAKE_C_COMPILE_OBJECT}")
        string(REPLACE "/FS" "" CMAKE_C_COMPILE_OBJECT "${CMAKE_C_COMPILE_OBJECT}")
        if(CMAKE_CROSSCOMPILING)
            set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MANIFEST:NO /INCREMENTAL:NO")
            set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} /MANIFEST:NO /INCREMENTAL:NO")
            string(REPLACE "/INCREMENTAL" "/INCREMENTAL:NO" CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG}")
            string(REPLACE "/INCREMENTAL" "/INCREMENTAL:NO" CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG}")
        endif()
    endif()
endif()

set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)

# Enforce strictly C89 standard
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# CMake options for matrix builds
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(BUILD_TESTING "Build test suite" ON)
set(LIBMOUNTSANDBOX_CRT_LINKAGE "Shared" CACHE STRING "MSVC CRT Linkage: Static or Shared")
set(LIBMOUNTSANDBOX_CHARSET "Unicode" CACHE STRING "Charset to use: Unicode or ANSI")
set(LIBMOUNTSANDBOX_THREADING "Multi-threaded" CACHE STRING "Threading: Multi-threaded or Single-threaded")
set(LIBMOUNTSANDBOX_MSVC_RTC "" CACHE STRING "MSVC Runtime Checks: RTC1, RTCs, RTCu, or empty")
option(LIBMOUNTSANDBOX_LTO "Enable Link-Time Optimization (LTO)" OFF)
option(LIBMOUNTSANDBOX_ENABLE_COVERAGE "Enable code coverage (gcov)" OFF)

# Support c-ci CDD_* cache variables
set(CDD_CHARSET "" CACHE STRING "")
set(CDD_DEPS "" CACHE STRING "")
set(CDD_MSVC_RTC "" CACHE STRING "")
set(CDD_THREADING "" CACHE STRING "")
set(CDD_CRT_LINKAGE "" CACHE STRING "")

if(NOT "${CDD_CRT_LINKAGE}" STREQUAL "")
    set(LIBMOUNTSANDBOX_CRT_LINKAGE "${CDD_CRT_LINKAGE}" CACHE STRING "" FORCE)
endif()
if(NOT "${CDD_CHARSET}" STREQUAL "")
    set(LIBMOUNTSANDBOX_CHARSET "${CDD_CHARSET}" CACHE STRING "" FORCE)
endif()
if(NOT "${CDD_THREADING}" STREQUAL "")
    set(LIBMOUNTSANDBOX_THREADING "${CDD_THREADING}" CACHE STRING "" FORCE)
endif()
if(NOT "${CDD_MSVC_RTC}" STREQUAL "")
    set(LIBMOUNTSANDBOX_MSVC_RTC "${CDD_MSVC_RTC}" CACHE STRING "" FORCE)
endif()

if(LIBMOUNTSANDBOX_LTO OR CMAKE_INTERPROCEDURAL_OPTIMIZATION)
    if(MINGW AND CMAKE_C_COMPILER_ID MATCHES "GNU")
        if(CMAKE_GCC_AR)
            set(CMAKE_AR "${CMAKE_GCC_AR}")
        endif()
        if(CMAKE_GCC_RANLIB)
            set(CMAKE_RANLIB "${CMAKE_GCC_RANLIB}")
        endif()
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffat-lto-objects")
    endif()
    include(CheckIPOSupported)
    check_ipo_supported(RESULT lto_supported OUTPUT lto_error)
    if(lto_supported)
        set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()
endif()

if(LIBMOUNTSANDBOX_ENABLE_COVERAGE)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage -O0 -g")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} --coverage")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} --coverage")
    endif()
endif()

# Strict compiler flags
set(SANDBOX_STRICT_FLAGS "")
set(SANDBOX_COMPILE_DEFS "")

if(MSVC)
    if(NOT DEFINED CMAKE_MSVC_RUNTIME_LIBRARY OR "${CMAKE_MSVC_RUNTIME_LIBRARY}" STREQUAL "")
        if(LIBMOUNTSANDBOX_CRT_LINKAGE STREQUAL "Static")
            set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
        else()
            set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
        endif()
    endif()

    list(APPEND SANDBOX_STRICT_FLAGS "/W4" "/WX")
    if(NOT "${LIBMOUNTSANDBOX_MSVC_RTC}" STREQUAL "" AND NOT "${LIBMOUNTSANDBOX_MSVC_RTC}" STREQUAL "OFF")
        list(APPEND SANDBOX_STRICT_FLAGS "/${LIBMOUNTSANDBOX_MSVC_RTC}")
    endif()

    if(LIBMOUNTSANDBOX_CHARSET STREQUAL "Unicode" OR LIBMOUNTSANDBOX_CHARSET STREQUAL "UNICODE")
        list(APPEND SANDBOX_COMPILE_DEFS "UNICODE" "_UNICODE")
    elseif(LIBMOUNTSANDBOX_CHARSET STREQUAL "ANSI")
        list(APPEND SANDBOX_COMPILE_DEFS "_MBCS")
    endif()
elseif(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|AppleClang")
    list(APPEND SANDBOX_STRICT_FLAGS
        "-std=c89"
        "-pedantic"
        "-Wall"
        "-Wextra"
        "-Werror"
        "-Wstrict-prototypes"
        "-Wmissing-prototypes"
        "-Wold-style-definition"
        "-Wdeclaration-after-statement"
        "-Wshadow"
        "-Wpointer-arith"
        "-Wcast-align"
    )
    if(MINGW)
        list(APPEND SANDBOX_COMPILE_DEFS "__USE_MINGW_ANSI_STDIO=1")
    elseif(CYGWIN)
        list(APPEND SANDBOX_COMPILE_DEFS "_DEFAULT_SOURCE")
    endif()
endif()

if(LIBMOUNTSANDBOX_THREADING STREQUAL "Single-threaded" OR LIBMOUNTSANDBOX_THREADING STREQUAL "OFF")
    list(APPEND SANDBOX_COMPILE_DEFS "LIBMOUNTSANDBOX_SINGLE_THREADED=1")
else()
    list(APPEND SANDBOX_COMPILE_DEFS "LIBMOUNTSANDBOX_MULTITHREADED=1")
endif()

# Fetch dependencies
include(FetchContent)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../c-fs/CMakeLists.txt")
    FetchContent_Declare(
        c_fs
        SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../c-fs"
    )
else()
    FetchContent_Declare(
        c_fs
        URL https://github.com/SamuelMarks/c-fs/archive/refs/heads/master.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
endif()

set(BUILD_TESTING_SAVED "${BUILD_TESTING}")
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(c_fs)
set(BUILD_TESTING "${BUILD_TESTING_SAVED}" CACHE BOOL "" FORCE)

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../greatest/greatest.h")
    FetchContent_Declare(
        greatest
        SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../greatest"
    )
else()
    FetchContent_Declare(
        greatest
        URL https://github.com/SamuelMarks/greatest/archive/refs/heads/master.zip
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
endif()
FetchContent_MakeAvailable(greatest)

# Define source files for the sandbox core library
set(SANDBOX_SOURCES
    src/sandbox.c
    src/log.c
    src/sandbox_common.c
    src/engine_dummy.c
    src/engine_docker.c
    src/engine_podman.c
    src/engine_gvisor.c
    src/engine_wasmtime.c
    src/engine_appcontainer.c
    src/engine_native.c
)

# Static library target
add_library(sandbox_lib STATIC ${SANDBOX_SOURCES})
set_target_properties(sandbox_lib PROPERTIES OUTPUT_NAME "mountsandbox_static")
target_include_directories(sandbox_lib PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_options(sandbox_lib PRIVATE ${SANDBOX_STRICT_FLAGS})
target_compile_definitions(sandbox_lib PRIVATE ${SANDBOX_COMPILE_DEFS})
target_link_libraries(sandbox_lib PRIVATE cfs)

# Shared library target for FFI (Python, TS, Go, Rust, Ruby, Swift, Kotlin, C#)
set(SANDBOX_BUILD_SHARED_TARGET TRUE)
if(EMSCRIPTEN)
    set(SANDBOX_BUILD_SHARED_TARGET FALSE)
elseif(MSVC)
    if(LIBMOUNTSANDBOX_CRT_LINKAGE STREQUAL "Static" OR CMAKE_MSVC_RUNTIME_LIBRARY MATCHES "^MultiThreaded(Debug)?$")
        set(SANDBOX_BUILD_SHARED_TARGET FALSE)
    endif()
endif()

if(SANDBOX_BUILD_SHARED_TARGET)
    add_library(sandbox_shared SHARED ${SANDBOX_SOURCES})
    set_target_properties(sandbox_shared PROPERTIES OUTPUT_NAME "mountsandbox")
    if(MSVC)
        set_target_properties(sandbox_shared PROPERTIES INTERPROCEDURAL_OPTIMIZATION OFF)
    endif()
    target_include_directories(sandbox_shared PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_compile_options(sandbox_shared PRIVATE ${SANDBOX_STRICT_FLAGS})
    target_compile_definitions(sandbox_shared PRIVATE ${SANDBOX_COMPILE_DEFS})
    target_link_libraries(sandbox_shared PRIVATE cfs)
    if(WIN32)
        set_target_properties(sandbox_shared PROPERTIES PREFIX "")
    endif()
endif()

# Main CLI executable
add_executable(mountsandbox src/main.c)
target_include_directories(mountsandbox PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_compile_options(mountsandbox PRIVATE ${SANDBOX_STRICT_FLAGS})
target_compile_definitions(mountsandbox PRIVATE ${SANDBOX_COMPILE_DEFS})
target_link_libraries(mountsandbox PRIVATE sandbox_lib)

# Unit Testing
if(BUILD_TESTING)
    find_program(MEMORYCHECK_COMMAND NAMES valgrind)
    if(MEMORYCHECK_COMMAND)
        set(MEMORYCHECK_COMMAND_OPTIONS "--leak-check=full --show-leak-kinds=all --track-origins=yes -q --error-exitcode=1")
    endif()
    include(CTest)
    enable_testing()
    add_executable(test_sandbox
        tests/test_sandbox.c
        ${SANDBOX_SOURCES}
    )
    target_include_directories(test_sandbox PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${greatest_SOURCE_DIR}"
    )
    target_compile_options(test_sandbox PRIVATE ${SANDBOX_STRICT_FLAGS})
    target_compile_definitions(test_sandbox PRIVATE
        ${SANDBOX_COMPILE_DEFS}
        SANDBOX_ENABLE_MOCKS=1
        SANDBOX_TESTING_MAIN=1
    )
    target_link_libraries(test_sandbox PRIVATE cfs)

    add_test(NAME run_unit_tests COMMAND test_sandbox)
    add_test(NAME test_cli_help COMMAND mountsandbox --help)
    add_test(NAME test_cli_version COMMAND mountsandbox --version)
    add_test(NAME test_cli_dummy COMMAND mountsandbox --engine=dummy -- echo hello)
    add_test(NAME test_cli_all_options COMMAND mountsandbox --engine=dummy --no-network --env=A=B --mount=/tmp --ro-mount=/var --timeout=10 --memory-mb=100 --cpu-pct=50 --drop-privs --uid=1000 --gid=1000 --deny-syscall=ptrace -- echo tested)
endif()
