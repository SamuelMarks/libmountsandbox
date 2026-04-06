/**
 * \file engine_appcontainer.c
 * \brief Windows AppContainer sandbox implementation.
 *
 * This engine maps the execution of a command into a native Windows
 * AppContainer, providing strict isolation compared to standard Job Objects.
 * On non-Windows platforms, it serves as a stub.
 */

#include "sandbox.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#include <io.h>

/* Dynamic loading typedefs and constants for C89 / MSVC 2005 compatibility */
typedef HRESULT (WINAPI *CreateAppContainerProfile_t)(PCWSTR, PCWSTR, PCWSTR, const void*, DWORD, PSID*);
typedef HRESULT (WINAPI *DeleteAppContainerProfile_t)(PCWSTR);
typedef BOOL (WINAPI *InitializeProcThreadAttributeList_t)(LPVOID, DWORD, DWORD, PSIZE_T);
typedef BOOL (WINAPI *UpdateProcThreadAttribute_t)(LPVOID, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
typedef void (WINAPI *DeleteProcThreadAttributeList_t)(LPVOID);

#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif

#ifndef PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
#define PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES 0x00020009
#endif

typedef struct _MSB_SECURITY_CAPABILITIES {
    PSID AppContainerSid;
    PVOID Capabilities;
    DWORD CapabilityCount;
    DWORD Reserved;
} MSB_SECURITY_CAPABILITIES;

typedef struct _MSB_STARTUPINFOEXA {
    STARTUPINFOA StartupInfo;
    LPVOID lpAttributeList;
} MSB_STARTUPINFOEXA;

static int read_fp_to_buffer(FILE *fp, char **buf, size_t *size) {
    long fsize;
    if (!fp || !buf || !size) return -1;
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    rewind(fp);
    if (fsize < 0) fsize = 0;
    *buf = (char *)malloc((size_t)fsize + 1);
    if (*buf) {
        size_t read_bytes = fread(*buf, 1, (size_t)fsize, fp);
        (*buf)[read_bytes] = '\0';
        *size = read_bytes;
        return 0;
    } else {
        *size = 0;
        return -1;
    }
}

static int appcontainer_init(void) {
    return 0;
}

static int appcontainer_execute(const sandbox_config_t *config, int argc, char **argv) {
    HMODULE hUserEnv = LoadLibraryA("userenv.dll");
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    
    CreateAppContainerProfile_t pCreateAppContainerProfile = NULL;
    DeleteAppContainerProfile_t pDeleteAppContainerProfile = NULL;
    InitializeProcThreadAttributeList_t pInitializeProcThreadAttributeList = NULL;
    UpdateProcThreadAttribute_t pUpdateProcThreadAttribute = NULL;
    DeleteProcThreadAttributeList_t pDeleteProcThreadAttributeList = NULL;

    MSB_SECURITY_CAPABILITIES sc;
    MSB_STARTUPINFOEXA siex;
    PROCESS_INFORMATION pi;
    PSID appContainerSid = NULL;
    WCHAR acName[256];
    WCHAR acDisplayName[256];
    WCHAR acDescription[256];
    SIZE_T attrListSize = 0;
    
    int i, status = -1;
    size_t cmdline_len = 0;
    char *cmdline;
    DWORD exit_code;
    FILE *out_fp = NULL;
    FILE *err_fp = NULL;

    const char *start_dir = NULL;

    if (!config || !argv) {
        if (hUserEnv) FreeLibrary(hUserEnv);
        return -1;
    }

    if (hUserEnv) {
        pCreateAppContainerProfile = (CreateAppContainerProfile_t)GetProcAddress(hUserEnv, "CreateAppContainerProfile");
        pDeleteAppContainerProfile = (DeleteAppContainerProfile_t)GetProcAddress(hUserEnv, "DeleteAppContainerProfile");
    }
    if (hKernel32) {
        pInitializeProcThreadAttributeList = (InitializeProcThreadAttributeList_t)GetProcAddress(hKernel32, "InitializeProcThreadAttributeList");
        pUpdateProcThreadAttribute = (UpdateProcThreadAttribute_t)GetProcAddress(hKernel32, "UpdateProcThreadAttribute");
        pDeleteProcThreadAttributeList = (DeleteProcThreadAttributeList_t)GetProcAddress(hKernel32, "DeleteProcThreadAttributeList");
    }

    if (!pCreateAppContainerProfile || !pInitializeProcThreadAttributeList || !pUpdateProcThreadAttribute) {
        fprintf(stderr, "[libmountsandbox] AppContainer API not available on this version of Windows.\n");
        if (hUserEnv) FreeLibrary(hUserEnv);
        return -1;
    }

    if (config->stdout_buffer) out_fp = tmpfile();
    if (config->max_network_mbps > 0) {
        fprintf(stderr, "[libmountsandbox] Warning: Network bandwidth throttling (max_network_mbps) is not natively enforced by this engine.\n");
    }
    if (config->stderr_buffer) err_fp = tmpfile();

    if (config->mounts && config->mount_count > 0) {
        start_dir = config->mounts[0].dir;
    }

    /* Build command line string */
    for (i = 0; i < argc; i++) {
        cmdline_len += strlen(argv[i]) + 3;
    }
    cmdline = (char *)malloc(cmdline_len + 1);
    if (!cmdline) {
        if (hUserEnv) FreeLibrary(hUserEnv);
        return -1;
    }
    cmdline[0] = '\0';
    for (i = 0; i < argc; i++) {
        strcat(cmdline, "\"");
        strcat(cmdline, argv[i]);
        strcat(cmdline, "\" ");
    }

    /* Create Profile */
    MultiByteToWideChar(CP_UTF8, 0, "LibMountSandboxAC", -1, acName, 256);
    MultiByteToWideChar(CP_UTF8, 0, "LibMountSandbox AppContainer", -1, acDisplayName, 256);
    MultiByteToWideChar(CP_UTF8, 0, "Sandbox isolated environment", -1, acDescription, 256);

    if (FAILED(pCreateAppContainerProfile(acName, acDisplayName, acDescription, NULL, 0, &appContainerSid))) {
        fprintf(stderr, "[libmountsandbox] CreateAppContainerProfile failed.\n");
        free(cmdline);
        if (hUserEnv) FreeLibrary(hUserEnv);
        return -1;
    }

    memset(&sc, 0, sizeof(sc));
    sc.AppContainerSid = appContainerSid;

    memset(&siex, 0, sizeof(siex));
    siex.StartupInfo.cb = sizeof(siex);

    pInitializeProcThreadAttributeList(NULL, 1, 0, &attrListSize);
    siex.lpAttributeList = malloc(attrListSize);
    
    if (!siex.lpAttributeList || !pInitializeProcThreadAttributeList(siex.lpAttributeList, 1, 0, &attrListSize)) {
        fprintf(stderr, "[libmountsandbox] InitializeProcThreadAttributeList failed.\n");
        pDeleteAppContainerProfile(acName);
        if (appContainerSid) FreeSid(appContainerSid);
        free(cmdline);
        if (hUserEnv) FreeLibrary(hUserEnv);
        return -1;
    }

    if (!pUpdateProcThreadAttribute(siex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &sc, sizeof(sc), NULL, NULL)) {
        fprintf(stderr, "[libmountsandbox] UpdateProcThreadAttribute failed.\n");
        pDeleteProcThreadAttributeList(siex.lpAttributeList);
        free(siex.lpAttributeList);
        pDeleteAppContainerProfile(acName);
        if (appContainerSid) FreeSid(appContainerSid);
        free(cmdline);
        if (hUserEnv) FreeLibrary(hUserEnv);
        return -1;
    }

    if (out_fp || err_fp) {
        siex.StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
        if (out_fp) siex.StartupInfo.hStdOutput = (HANDLE)_get_osfhandle(_fileno(out_fp));
        else siex.StartupInfo.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        
        if (err_fp) siex.StartupInfo.hStdError = (HANDLE)_get_osfhandle(_fileno(err_fp));
        else siex.StartupInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        
        siex.StartupInfo.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    }
    
    memset(&pi, 0, sizeof(pi));

    if (config->env_vars && config->env_count > 0) {
        size_t e;
        for (e = 0; e < config->env_count; e++) {
            _putenv((char *)config->env_vars[e]);
        }
    }

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, TRUE, 
                        EXTENDED_STARTUPINFO_PRESENT, 
                        NULL, start_dir, (STARTUPINFOA*)&siex, &pi)) {
        fprintf(stderr, "[libmountsandbox] CreateProcessA failed (%lu)\n", GetLastError());
    } else {
        if (config->timeout_secs > 0) {
            if (WaitForSingleObject(pi.hProcess, config->timeout_secs * 1000) == WAIT_TIMEOUT) {
                TerminateProcess(pi.hProcess, 1);
                status = 124;
            } else {
                if (GetExitCodeProcess(pi.hProcess, &exit_code)) {
                    status = (int)exit_code;
                }
            }
        } else {
            WaitForSingleObject(pi.hProcess, INFINITE);
            if (GetExitCodeProcess(pi.hProcess, &exit_code)) {
                status = (int)exit_code;
            }
        }
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    if (out_fp && config->stdout_buffer) { if (read_fp_to_buffer(out_fp, config->stdout_buffer, config->stdout_size) != 0) { status = -1; } fclose(out_fp); }
    if (err_fp && config->stderr_buffer) { if (read_fp_to_buffer(err_fp, config->stderr_buffer, config->stderr_size) != 0) { status = -1; } fclose(err_fp); }

    pDeleteProcThreadAttributeList(siex.lpAttributeList);
    free(siex.lpAttributeList);
    pDeleteAppContainerProfile(acName);
    if (appContainerSid) FreeSid(appContainerSid);
    free(cmdline);
    if (hUserEnv) FreeLibrary(hUserEnv);

    return status;
}

#else
/* ========================================================================= */
/* Unsupported Platform Stub                                                 */
/* ========================================================================= */
static int appcontainer_init(void) {
    return 0;
}

static int appcontainer_execute(const sandbox_config_t *config, int argc, char **argv) {
    (void)config; (void)argc; (void)argv;
    fprintf(stderr, "[libmountsandbox] AppContainer sandbox is only supported on Windows.\n");
    return -1;
}
#endif


static sandbox_process_t* appcontainer_execute_async(const sandbox_config_t *config, int argc, char **argv) {
    (void)config; (void)argc; (void)argv;
    fprintf(stderr, "[libmountsandbox] Async execution is a work in progress for appcontainer. Falling back to sync.\n");
    return NULL;
}

static int appcontainer_wait_process(sandbox_process_t *process, int *exit_status) {
    (void)process; (void)exit_status;
    return -1;
}

static void appcontainer_free_process(sandbox_process_t *process) {
    (void)process;
}

static void appcontainer_cleanup(void) {
}

/**
 * \brief The AppContainer sandbox engine export.
 */
sandbox_engine_t engine_appcontainer = {
    "appcontainer",
    "Windows AppContainer strict isolation sandbox",
    appcontainer_init,
    appcontainer_execute,
    appcontainer_execute_async,
    appcontainer_wait_process,
    appcontainer_free_process,
    appcontainer_cleanup
};
