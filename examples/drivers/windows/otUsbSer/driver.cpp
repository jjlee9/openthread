/*
 *    Copyright (c) 2016, The OpenThread Authors.
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *    WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *    DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY
 *    DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *    (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *    LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *    ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *    (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file
 *   This module has code to deal with loading and unloading of the driver 
 */

extern "C"
{
#include <ntddk.h>
#include <wdf.h>
}

#include "platform/logging-windows.h"
#include "driver.tmh"
#include <initguid.h>

extern "C" DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD   otUsbSerEvtDeviceAdd;
EVT_WDF_DRIVER_UNLOAD       otUsbSerEvtDriverUnload;
EVT_WDF_IO_QUEUE_IO_DEFAULT otUsbSerEvtIoDefault;
EVT_WDF_IO_QUEUE_IO_DEFAULT otUsbSerPdoEvtIoDefault;

typedef struct DEVICE_CONTEXT { ULONG MagicNumber; } *PDEVICE_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, otUsbSerGetDeviceContext);

enum { DEVICE_CONTEXT_MAGIC = 'otUD' };

// {B39ED6E1-F9AA-46EC-96DF-52DFFF434F23}
DEFINE_GUID(GUID_OPENTHREAD_TUNNEL_DEVICE,
    0xb39ed6e1, 0xf9aa, 0x46ec, 0x96, 0xdf, 0x52, 0xdf, 0xff, 0x43, 0x4f, 0x23);

_Use_decl_annotations_
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    WPP_INIT_TRACING(DriverObject, RegistryPath);

    LogFuncEntry(DRIVER_DEFAULT);

    WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, otUsbSerEvtDeviceAdd);
    config.DriverPoolTag = DEVICE_CONTEXT_MAGIC;
    config.EvtDriverUnload = otUsbSerEvtDriverUnload;

    // Create the framework driver object
    NTSTATUS status = 
        WdfDriverCreate(DriverObject,
            RegistryPath,
            WDF_NO_OBJECT_ATTRIBUTES,
            &config,
            NULL);

    LogFuncExitNT(DRIVER_DEFAULT, status);

    if (!NT_SUCCESS(status))
    {
        WPP_CLEANUP(DriverObject);
    }

    return status;

}

_Use_decl_annotations_
VOID
otUsbSerEvtDriverUnload(
    _In_ WDFDRIVER Driver
    )
{
    WPP_CLEANUP(Driver);
}

_Use_decl_annotations_
NTSTATUS
otUsbSerEvtDeviceAdd(
    _In_ WDFDRIVER Driver,
    _Inout_ PWDFDEVICE_INIT DeviceInit
    )
{

    NTSTATUS                     status;
    WDF_OBJECT_ATTRIBUTES        wdfObjectAttr;
    WDFDEVICE                    wdfDevice, wdfChild = WDF_NO_HANDLE;
    WDFQUEUE                     wdfQueue;
    PDEVICE_CONTEXT              devCont;
    PNP_BUS_INFORMATION          busInfo = { GUID_OPENTHREAD_TUNNEL_DEVICE, PNPBus, 0 };
    PWDFDEVICE_INIT              pChildDeviceInit = NULL;
    WDF_IO_QUEUE_CONFIG          queueConfig;
    WDF_FILEOBJECT_CONFIG        fileObjectConfig;
    WDF_DEVICE_POWER_CAPABILITIES powerCaps;

    // \0 in the end is for double termination - required for MULTI_SZ string
    DECLARE_CONST_UNICODE_STRING(hardwareId, L"{416413DC-E0C2-4EBF-88D7-A0A89A617FDB}\\otUsbSer\0");
    DECLARE_CONST_UNICODE_STRING(deviceText, L"OpenThread Tunnel Miniport");
    DECLARE_CONST_UNICODE_STRING(deviceLoc, L"OpenThread USB Device");

    UNREFERENCED_PARAMETER(Driver);

    LogFuncEntry(DRIVER_DEFAULT);

    WDF_FILEOBJECT_CONFIG_INIT(&fileObjectConfig, NULL, NULL, NULL);

    fileObjectConfig.FileObjectClass = WdfFileObjectNotRequired; // So we can use SEND_AND_FORGET
    fileObjectConfig.AutoForwardCleanupClose = WdfTrue; //forward create, cleanup and close IRPs down to next driver stack
    WdfDeviceInitSetFileObjectConfig(DeviceInit, &fileObjectConfig, WDF_NO_OBJECT_ATTRIBUTES);

    // Disallow Dx states
    WDF_DEVICE_POWER_CAPABILITIES_INIT(&powerCaps);
    powerCaps.DeviceD1 = WdfFalse;
    powerCaps.DeviceD2 = WdfFalse;
    powerCaps.WakeFromD0 = WdfFalse;
    powerCaps.WakeFromD1 = WdfFalse;
    powerCaps.WakeFromD2 = WdfFalse;
    powerCaps.WakeFromD3 = WdfFalse;
    for (int i = 0; i < _ARRAYSIZE(powerCaps.DeviceState); i++)
    {
        powerCaps.DeviceState[i] = PowerDeviceUnspecified;
    }

    //
    // We're a filter, so mark our device init structure
    //  as such. This will do all sorts of lovely things,
    //  such as pass requests that we don't care about
    //  to the FDO unharmed
    //
    WdfFdoInitSetFilter(DeviceInit);

    //
    // We don't know what our device type is going to be yet
    //  (we're an agnostic filter, remember?) So mark it as
    //  UNKNOWN. When we call WdfDeviceCreate the framework
    //  will do all the legwork for us to determine what the
    //  appropriate type is.
    //
    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_UNKNOWN);

    //
    // Setup our device attributes to have our context type
    //
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&wdfObjectAttr, DEVICE_CONTEXT);

    //
    // And create our WDF device. This does a multitude of things,
    //  including:
    //
    //  1) Create a WDM device object
    //  2) Attach the device object to the filtered device object
    //  3) Propagate all the flags and characteristics of the 
    //     target device to our filter device. So, for example, if 
    //     the target device is setup for direct I/O our filter 
    //     device will also be setup for direct I/O
    //
    status = WdfDeviceCreate(&DeviceInit, &wdfObjectAttr, &wdfDevice);

    if (!NT_SUCCESS(status))
    {
        LogError(DRIVER_DEFAULT, "WdfDeviceCreate failed %!STATUS!\n", status);
        return status;
    }

    WdfDeviceSetPowerCapabilities(wdfDevice, &powerCaps);


    //
    // Get our filter context
    //
    devCont = otUsbSerGetDeviceContext(wdfDevice);

    //
    // Initialize our context
    //
    devCont->MagicNumber = DEVICE_CONTEXT_MAGIC;

    //
    // Generally filter drivers don't create queues if they don't handle I/O 
    // since framework by default passes them down. However, in this case, 
    // Child PDOs are configured to pass I/O requests to parent (this filter 
    // driver), so we need to have a queue to receive those requests and then 
    // forward them down to the lower stack. 
    // 
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDefault = otUsbSerEvtIoDefault;
    queueConfig.PowerManaged = WdfFalse;
    status = WdfIoQueueCreate(wdfDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &wdfQueue);
    if (!NT_SUCCESS(status))
    {
        LogError(DRIVER_DEFAULT, "WdfIoQueueCreate(bus) failed %!STATUS!\n", status);
        goto FAIL;
    }

    status = WdfDeviceConfigureRequestDispatching(wdfDevice, wdfQueue, WdfRequestTypeCreate);
    if (!NT_SUCCESS(status))
    {
        LogError(DRIVER_DEFAULT, "WdfDeviceConfigureRequestDispatching(create) failed %!STATUS!\n", status);
        goto FAIL;
    }

    WdfDeviceSetBusInformationForChildren(wdfDevice, &busInfo);
    pChildDeviceInit = WdfPdoInitAllocate(wdfDevice);
    if (NULL == pChildDeviceInit)
    {
        LogError(DRIVER_DEFAULT, "WdfPdoInitAllocate failed %!STATUS!\n", status);
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto FAIL;
    }

    WdfPdoInitAllowForwardingRequestToParent(pChildDeviceInit);
    WdfDeviceInitSetDeviceType(pChildDeviceInit, FILE_DEVICE_NETWORK);

    status = WdfPdoInitAssignDeviceID(pChildDeviceInit, &hardwareId);
    if (!NT_SUCCESS(status))
    {
        LogError(DRIVER_DEFAULT, "WdfPdoInitAssignDeviceID failed %!STATUS!\n", status);
        goto FAIL;
    }
    status = WdfPdoInitAddHardwareID(pChildDeviceInit, &hardwareId);
    if (!NT_SUCCESS(status))
    {
        LogError(DRIVER_DEFAULT, "WdfPdoInitAddHardwareID failed %!STATUS!\n", status);
        goto FAIL;
    }

    status = WdfPdoInitAddDeviceText(pChildDeviceInit, &deviceText, &deviceLoc, 0x409);
    if (!NT_SUCCESS(status))
    {
        LogError(DRIVER_DEFAULT, "WdfPdoInitAddDeviceText failed %!STATUS!\n", status);
        goto FAIL;
    }

    WdfPdoInitSetDefaultLocale(pChildDeviceInit, 0x409);

    WDF_FILEOBJECT_CONFIG_INIT(&fileObjectConfig, NULL, NULL, NULL);

    fileObjectConfig.FileObjectClass = WdfFileObjectNotRequired; // So we can use SEND_AND_FORGET
    fileObjectConfig.AutoForwardCleanupClose = WdfTrue; //forward create, cleanup and close IRPs down to next driver stack
    WdfDeviceInitSetFileObjectConfig(pChildDeviceInit, &fileObjectConfig, WDF_NO_OBJECT_ATTRIBUTES);

    // Can only be opened once by the  Miniport
    WdfDeviceInitSetExclusive(pChildDeviceInit, TRUE);

    status = WdfDeviceCreate(&pChildDeviceInit, WDF_NO_OBJECT_ATTRIBUTES, &wdfChild);
    if (!NT_SUCCESS(status))
    {
        LogError(DRIVER_DEFAULT, "WdfDeviceCreate (child) failed %!STATUS!\n", status);
        goto FAIL;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchParallel);
    queueConfig.EvtIoDefault = otUsbSerPdoEvtIoDefault;
    status = WdfIoQueueCreate(wdfChild, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &wdfQueue);
    if (!NT_SUCCESS(status))
    {
        LogError(DRIVER_DEFAULT, "WdfIoQueueCreate(pdo) failed %!STATUS!\n", status);
        goto FAIL;
    }
    status = WdfDeviceConfigureRequestDispatching(wdfChild, wdfQueue, WdfRequestTypeCreate);
    if (!NT_SUCCESS(status))
    {
        LogError(DRIVER_DEFAULT, "WdfDeviceConfigureRequestDispatching(create) failed %!STATUS!\n", status);
        goto FAIL;
    }

    WdfDeviceSetPowerCapabilities(wdfChild, &powerCaps);

    status = WdfFdoAddStaticChild(wdfDevice, wdfChild);
    if (!NT_SUCCESS(status))
    {
        LogError(DRIVER_DEFAULT, "WdfFdoAddStaticChild failed %!STATUS!\n", status);
        goto FAIL;
    }

    //
    // Success!
    //
    LogFuncExitNT(DRIVER_DEFAULT, status);
    return status;

FAIL:
    if (WDF_NO_HANDLE != wdfChild)
    {
        WdfObjectDelete(wdfChild);
        wdfChild = WDF_NO_HANDLE;
    }
    if (NULL != pChildDeviceInit)
    {
        WdfDeviceInitFree(pChildDeviceInit);
        pChildDeviceInit = NULL;
    }

    LogFuncExitNT(DRIVER_DEFAULT, status);
    return status;
}

VOID otUsbSerEvtIoDefault(_In_ WDFQUEUE Queue, _In_ WDFREQUEST Request)
{
    LogFuncEntry(DRIVER_DEFAULT);

    // Format the request so we can forward it, unmodified
    WdfRequestFormatRequestUsingCurrentType(Request);

    // Configure for 'fire and forget'
    WDF_REQUEST_SEND_OPTIONS options;
    WDF_REQUEST_SEND_OPTIONS_INIT(&options, WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

    // Forward the request
    if (!WdfRequestSend(Request, WdfDeviceGetIoTarget(WdfIoQueueGetDevice(Queue)), &options))
    {
        WdfRequestComplete(Request, WdfRequestGetStatus(Request));
    }

    LogFuncExit(DRIVER_DEFAULT);
}

_Use_decl_annotations_
VOID
otUsbSerPdoEvtIoDefault(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request
    )
{
    LogFuncEntry(DRIVER_DEFAULT);

    // Get the parent device
    WDFDEVICE parentDevice = WdfPdoGetParent(WdfIoQueueGetDevice(Queue));

    WDF_REQUEST_FORWARD_OPTIONS forwardOptions;
    WDF_REQUEST_FORWARD_OPTIONS_INIT(&forwardOptions);

    // Forwad to the parent device
    NTSTATUS status = 
        WdfRequestForwardToParentDeviceIoQueue(
            Request,
            WdfDeviceGetDefaultQueue(parentDevice),
            &forwardOptions);

    if (!NT_SUCCESS(status))
    {
        WdfRequestComplete(Request, status);
    }

    LogFuncExit(DRIVER_DEFAULT);
}
