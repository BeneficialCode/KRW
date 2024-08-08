#pragma once

/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2022
*
*  TITLE:       ECHODRV.H
*
*  VERSION:     1.33
*
*  DATE:        16 Jul 2023
*
*  Inspect Element LTD spyware (anticheat) driver interface header.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/

#include <Windows.h>

//
// Echo.ac driver uses a ridiculous IOCTL scheme which could be a side effect of intense copy-paste. 
//

#define ECHODRV_DEVICE_TYPE         (DWORD)0x9E6A
#define ECHODRV_INTERFACE_TYPE_1    (DWORD)0xE622
#define ECHODRV_INTERFACE_TYPE_2    (DWORD)0x60A2

#define ECHODRV_FUNCTION_REGISTER       (DWORD)0x165
#define ECHODRV_FUNCTION_OPEN_PROCESS   (DWORD)0x92
#define ECHODRV_FUNCTION_COPYVM         (DWORD)0x849

#define IOCTL_ECHODRV_REGISTER          \
    CTL_CODE(ECHODRV_DEVICE_TYPE, ECHODRV_FUNCTION_REGISTER, METHOD_BUFFERED, FILE_ANY_ACCESS) //0x9E6A0594

#define IOCTL_ECHODRV_OPEN_PROCESS      \
    CTL_CODE(ECHODRV_INTERFACE_TYPE_1, ECHODRV_FUNCTION_OPEN_PROCESS, METHOD_BUFFERED, FILE_READ_ACCESS) //0xE6224248

#define IOCTL_ECHODRV_COPYVM            \
    CTL_CODE(ECHODRV_INTERFACE_TYPE_2, ECHODRV_FUNCTION_COPYVM, METHOD_BUFFERED, FILE_READ_ACCESS) //0x60A26124

typedef struct _ECHODRV_REGISTER {
    _In_ PUCHAR pvSignature;
    _In_ SIZE_T cbSignature;
    _Out_ BOOL bSuccess;
    _Out_ DWORD UniqCode; //0x1000 for call
} ECHODRV_REGISTER, * PECHODRV_REGISTER;

typedef struct _ECHODRV_VALIDATE_PROCESS {
    _In_ DWORD ProcessId;
    _In_ ACCESS_MASK DesiredAccess;
    _Out_ HANDLE ProcessHandle;
    _Out_ BOOL bSuccess;
    _Out_ DWORD UniqCode; //0x1001 for call
} ECHODRV_VALIDATE_PROCESS, * PECHODRV_VALIDATE_PROCESS;

typedef struct _ECHODRV_COPYVM_REQUEST {
    _In_ HANDLE ProcessHandle;
    _In_ PVOID FromAddress;
    _In_ PVOID ToAddress;
    _In_ SIZE_T BufferSize;
    _Out_ SIZE_T NumberOfBytesCopied;
    _Out_ BOOL bSuccess;
    _Out_ DWORD UniqCode; //0x1002 for call
} ECHODRV_COPYVM_REQUEST, * PECHODRV_COPY_REQUEST;

BOOL WINAPI EchoDrvRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);

BOOL WINAPI EchoDrvUnregisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param);

BOOL WINAPI EchoDrvReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);

BOOL WINAPI EchoDrvWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes);


typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemVerifierAddDriverInformation,
    SystemVerifierRemoveDriverInformation,
    SystemProcessorIdleInformation,
    SystemLegacyDriverInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemVerifierThunkExtend,
    SystemSessionProcessInformation,
    SystemLoadGdiDriverInSystemSpace,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchdogTimerHandler,
    SystemWatchdogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformation,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    MaxSystemInfoClass

} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE {
    ULONG                Reserved1;
    ULONG                Reserved2;
    PVOID                ImageBaseAddress;
    ULONG                ImageSize;
    ULONG                Flags;
    WORD                 Id;
    WORD                 Rank;
    WORD                 w018;
    WORD                 NameOffset;
    BYTE                 Name[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct SYSTEM_MODULE_INFORMATION {
    ULONG                ModulesCount;
    SYSTEM_MODULE        Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004
#define STATUS_SUCCESS 0x00000000

typedef NTSTATUS(WINAPI* NTQUERYSYSTEMINFORMATION)(IN ULONG, IN OUT PVOID, IN ULONG, OUT PULONG OPTIONAL);

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;