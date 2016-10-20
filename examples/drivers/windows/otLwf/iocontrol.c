/*
 *  Copyright (c) 2016, The OpenThread Authors.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the copyright holder nor the
 *     names of its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *  POSSIBILITY OF SUCH DAMAGE.
 */

#include "precomp.h"
#include "iocontrol.tmh"

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfTunIoCtl(
    _In_ PMS_FILTER     pFilter,
    _In_ PIRP           Irp
    );

typedef struct _OTLWF_IOCTL_HANDLER
{
    const char*             Name;
    OTLWF_OT_IOCTL_FUNC*    otFunc;
    OTLWF_TUN_IOCTL_FUNC*   tunFunc;
} OTLWF_IOCTL_HANDLER;

OTLWF_IOCTL_HANDLER IoCtls[] = 
{
    { "IOCTL_OTLWF_OT_ENABLED",                     NULL },
    { "IOCTL_OTLWF_OT_INTERFACE",                   REF_IOCTL_FUNC_WITH_TUN(otInterface) },
    { "IOCTL_OTLWF_OT_THREAD",                      REF_IOCTL_FUNC_WITH_TUN(otThread) },
    { "IOCTL_OTLWF_OT_ACTIVE_SCAN",                 REF_IOCTL_FUNC(otActiveScan) },
    { "IOCTL_OTLWF_OT_DISCOVER",                    REF_IOCTL_FUNC(otDiscover) },
    { "IOCTL_OTLWF_OT_CHANNEL",                     REF_IOCTL_FUNC_WITH_TUN(otChannel) },
    { "IOCTL_OTLWF_OT_CHILD_TIMEOUT",               REF_IOCTL_FUNC_WITH_TUN(otChildTimeout) },
    { "IOCTL_OTLWF_OT_EXTENDED_ADDRESS",            REF_IOCTL_FUNC_WITH_TUN(otExtendedAddress) },
    { "IOCTL_OTLWF_OT_EXTENDED_PANID",              REF_IOCTL_FUNC_WITH_TUN(otExtendedPanId) },
    { "IOCTL_OTLWF_OT_LEADER_RLOC",                 REF_IOCTL_FUNC_WITH_TUN(otLeaderRloc) },
    { "IOCTL_OTLWF_OT_LINK_MODE",                   REF_IOCTL_FUNC_WITH_TUN(otLinkMode) },
    { "IOCTL_OTLWF_OT_MASTER_KEY",                  REF_IOCTL_FUNC_WITH_TUN(otMasterKey) },
    { "IOCTL_OTLWF_OT_MESH_LOCAL_EID",              REF_IOCTL_FUNC_WITH_TUN(otMeshLocalEid) },
    { "IOCTL_OTLWF_OT_MESH_LOCAL_PREFIX",           REF_IOCTL_FUNC_WITH_TUN(otMeshLocalPrefix) },
    { "IOCTL_OTLWF_OT_NETWORK_DATA_LEADER",         NULL },
    { "IOCTL_OTLWF_OT_NETWORK_DATA_LOCAL",          NULL },
    { "IOCTL_OTLWF_OT_NETWORK_NAME",                REF_IOCTL_FUNC_WITH_TUN(otNetworkName) },
    { "IOCTL_OTLWF_OT_PAN_ID",                      REF_IOCTL_FUNC_WITH_TUN(otPanId) },
    { "IOCTL_OTLWF_OT_ROUTER_ROLL_ENABLED",         REF_IOCTL_FUNC(otRouterRollEnabled) },
    { "IOCTL_OTLWF_OT_SHORT_ADDRESS",               REF_IOCTL_FUNC(otShortAddress) },
    { "IOCTL_OTLWF_OT_UNICAST_ADDRESSES",           NULL },
    { "IOCTL_OTLWF_OT_ACTIVE_DATASET",              REF_IOCTL_FUNC(otActiveDataset) },
    { "IOCTL_OTLWF_OT_PENDING_DATASET",             REF_IOCTL_FUNC(otPendingDataset) },
    { "IOCTL_OTLWF_OT_LOCAL_LEADER_WEIGHT",         REF_IOCTL_FUNC(otLocalLeaderWeight) },
    { "IOCTL_OTLWF_OT_ADD_BORDER_ROUTER",           REF_IOCTL_FUNC(otAddBorderRouter) },
    { "IOCTL_OTLWF_OT_REMOVE_BORDER_ROUTER",        REF_IOCTL_FUNC(otRemoveBorderRouter) },
    { "IOCTL_OTLWF_OT_ADD_EXTERNAL_ROUTE",          REF_IOCTL_FUNC(otAddExternalRoute) },
    { "IOCTL_OTLWF_OT_REMOVE_EXTERNAL_ROUTE",       REF_IOCTL_FUNC(otRemoveExternalRoute) },
    { "IOCTL_OTLWF_OT_SEND_SERVER_DATA",            REF_IOCTL_FUNC(otSendServerData) },
    { "IOCTL_OTLWF_OT_CONTEXT_ID_REUSE_DELAY",      REF_IOCTL_FUNC(otContextIdReuseDelay) },
    { "IOCTL_OTLWF_OT_KEY_SEQUENCE_COUNTER",        REF_IOCTL_FUNC(otKeySequenceCounter) },
    { "IOCTL_OTLWF_OT_NETWORK_ID_TIMEOUT",          REF_IOCTL_FUNC(otNetworkIdTimeout) },
    { "IOCTL_OTLWF_OT_ROUTER_UPGRADE_THRESHOLD",    REF_IOCTL_FUNC(otRouterUpgradeThreshold) },
    { "IOCTL_OTLWF_OT_RELEASE_ROUTER_ID",           REF_IOCTL_FUNC(otReleaseRouterId) },
    { "IOCTL_OTLWF_OT_MAC_WHITELIST_ENABLED",       REF_IOCTL_FUNC(otMacWhitelistEnabled) },
    { "IOCTL_OTLWF_OT_ADD_MAC_WHITELIST",           REF_IOCTL_FUNC(otAddMacWhitelist) },
    { "IOCTL_OTLWF_OT_REMOVE_MAC_WHITELIST",        REF_IOCTL_FUNC(otRemoveMacWhitelist) },
    { "IOCTL_OTLWF_OT_MAC_WHITELIST_ENTRY",         REF_IOCTL_FUNC(otMacWhitelistEntry) },
    { "IOCTL_OTLWF_OT_CLEAR_MAC_WHITELIST",         REF_IOCTL_FUNC(otClearMacWhitelist) },
    { "IOCTL_OTLWF_OT_DEVICE_ROLE",                 REF_IOCTL_FUNC_WITH_TUN(otDeviceRole) },
    { "IOCTL_OTLWF_OT_CHILD_INFO_BY_ID",            REF_IOCTL_FUNC(otChildInfoById) },
    { "IOCTL_OTLWF_OT_CHILD_INFO_BY_INDEX",         REF_IOCTL_FUNC(otChildInfoByIndex) },
    { "IOCTL_OTLWF_OT_EID_CACHE_ENTRY",             REF_IOCTL_FUNC(otEidCacheEntry) },
    { "IOCTL_OTLWF_OT_LEADER_DATA",                 REF_IOCTL_FUNC(otLeaderData) },
    { "IOCTL_OTLWF_OT_LEADER_ROUTER_ID",            REF_IOCTL_FUNC(otLeaderRouterId) },
    { "IOCTL_OTLWF_OT_LEADER_WEIGHT",               REF_IOCTL_FUNC(otLeaderWeight) },
    { "IOCTL_OTLWF_OT_NETWORK_DATA_VERSION",        REF_IOCTL_FUNC(otNetworkDataVersion) },
    { "IOCTL_OTLWF_OT_PARTITION_ID",                REF_IOCTL_FUNC(otPartitionId) },
    { "IOCTL_OTLWF_OT_RLOC16",                      REF_IOCTL_FUNC(otRloc16) },
    { "IOCTL_OTLWF_OT_ROUTER_ID_SEQUENCE",          REF_IOCTL_FUNC(otRouterIdSequence) },
    { "IOCTL_OTLWF_OT_ROUTER_INFO",                 REF_IOCTL_FUNC(otRouterInfo) },
    { "IOCTL_OTLWF_OT_STABLE_NETWORK_DATA_VERSION", REF_IOCTL_FUNC(otStableNetworkDataVersion) },
    { "IOCTL_OTLWF_OT_MAC_BLACKLIST_ENABLED",       REF_IOCTL_FUNC(otMacBlacklistEnabled) },
    { "IOCTL_OTLWF_OT_ADD_MAC_BLACKLIST",           REF_IOCTL_FUNC(otAddMacBlacklist) },
    { "IOCTL_OTLWF_OT_REMOVE_MAC_BLACKLIST",        REF_IOCTL_FUNC(otRemoveMacBlacklist) },
    { "IOCTL_OTLWF_OT_MAC_BLACKLIST_ENTRY",         REF_IOCTL_FUNC(otMacBlacklistEntry) },
    { "IOCTL_OTLWF_OT_CLEAR_MAC_BLACKLIST",         REF_IOCTL_FUNC(otClearMacBlacklist) },
    { "IOCTL_OTLWF_OT_MAX_TRANSMIT_POWER",          REF_IOCTL_FUNC(otMaxTransmitPower) },
    { "IOCTL_OTLWF_OT_NEXT_ON_MESH_PREFIX",         REF_IOCTL_FUNC(otNextOnMeshPrefix) },
    { "IOCTL_OTLWF_OT_POLL_PERIOD",                 REF_IOCTL_FUNC(otPollPeriod) },
    { "IOCTL_OTLWF_OT_LOCAL_LEADER_PARTITION_ID",   REF_IOCTL_FUNC(otLocalLeaderPartitionId) },
    { "IOCTL_OTLWF_OT_ASSIGN_LINK_QUALITY",         REF_IOCTL_FUNC(otAssignLinkQuality) },
    { "IOCTL_OTLWF_OT_PLATFORM_RESET",              REF_IOCTL_FUNC(otPlatformReset) },
    { "IOCTL_OTLWF_OT_PARENT_INFO",                 REF_IOCTL_FUNC(otParentInfo) },
    { "IOCTL_OTLWF_OT_SINGLETON",                   REF_IOCTL_FUNC(otSingleton) },
    { "IOCTL_OTLWF_OT_MAC_COUNTERS",                REF_IOCTL_FUNC(otMacCounters) },
    { "IOCTL_OTLWF_OT_MAX_CHILDREN",                REF_IOCTL_FUNC(otMaxChildren) },
    { "IOCTL_OTLWF_OT_COMMISIONER_START",           REF_IOCTL_FUNC(otCommissionerStart) },
    { "IOCTL_OTLWF_OT_COMMISIONER_STOP",            REF_IOCTL_FUNC(otCommissionerStop) },
    { "IOCTL_OTLWF_OT_JOINER_START",                REF_IOCTL_FUNC(otJoinerStart) },
    { "IOCTL_OTLWF_OT_JOINER_STOP",                 REF_IOCTL_FUNC(otJoinerStop) },
    { "IOCTL_OTLWF_OT_FACTORY_EUI64",               REF_IOCTL_FUNC(otFactoryAssignedIeeeEui64) },
    { "IOCTL_OTLWF_OT_HASH_MAC_ADDRESS",            REF_IOCTL_FUNC(otHashMacAddress) },
    { "IOCTL_OTLWF_OT_ROUTER_DOWNGRADE_THRESHOLD",  REF_IOCTL_FUNC(otRouterDowngradeThreshold) },
    { "IOCTL_OTLWF_OT_COMMISSIONER_PANID_QUERY",    REF_IOCTL_FUNC(otCommissionerPanIdQuery) },
    { "IOCTL_OTLWF_OT_COMMISSIONER_ENERGY_SCAN",    REF_IOCTL_FUNC(otCommissionerEnergyScan) },
    { "IOCTL_OTLWF_OT_ROUTER_SELECTION_JITTER",     REF_IOCTL_FUNC(otRouterSelectionJitter) },
    { "IOCTL_OTLWF_OT_JOINER_UDP_PORT",             REF_IOCTL_FUNC(otJoinerUdpPort) },
    { "IOCTL_OTLWF_OT_SEND_DIAGNOSTIC_GET",         REF_IOCTL_FUNC(otSendDiagnosticGet) },
    { "IOCTL_OTLWF_OT_SEND_DIAGNOSTIC_RESET",       REF_IOCTL_FUNC(otSendDiagnosticReset) },
    { "IOCTL_OTLWF_OT_COMMISIONER_ADD_JOINER",      REF_IOCTL_FUNC(otCommissionerAddJoiner) },
    { "IOCTL_OTLWF_OT_COMMISIONER_REMOVE_JOINER",   REF_IOCTL_FUNC(otCommissionerRemoveJoiner) },
    { "IOCTL_OTLWF_OT_COMMISIONER_PROVISIONING_URL", REF_IOCTL_FUNC(otCommissionerProvisioningUrl) },
    { "IOCTL_OTLWF_OT_COMMISIONER_ANNOUNCE_BEGIN",  REF_IOCTL_FUNC(otCommissionerAnnounceBegin) },
    { "IOCTL_OTLWF_OT_ENERGY_SCAN",                 REF_IOCTL_FUNC(otEnergyScan) },
    { "IOCTL_OTLWF_OT_SEND_ACTIVE_GET",             REF_IOCTL_FUNC(otSendActiveGet) },
    { "IOCTL_OTLWF_OT_SEND_ACTIVE_SET",             REF_IOCTL_FUNC(otSendActiveSet) },
    { "IOCTL_OTLWF_OT_SEND_PENDING_GET",            REF_IOCTL_FUNC(otSendPendingGet) },
    { "IOCTL_OTLWF_OT_SEND_PENDING_SET",            REF_IOCTL_FUNC(otSendPendingSet) },
    { "IOCTL_OTLWF_OT_SEND_MGMT_COMMISSIONER_GET",  REF_IOCTL_FUNC(otSendMgmtCommissionerGet) },
    { "IOCTL_OTLWF_OT_SEND_MGMT_COMMISSIONER_SET",  REF_IOCTL_FUNC(otSendMgmtCommissionerSet) },
    { "IOCTL_OTLWF_OT_KEY_SWITCH_GUARDTIME",        REF_IOCTL_FUNC(otKeySwitchGuardtime) }
};

static_assert(ARRAYSIZE(IoCtls) == (MAX_OTLWF_IOCTL_FUNC_CODE - MIN_OTLWF_IOCTL_FUNC_CODE) + 1,
              "The IoCtl strings should be up to date with the actual IoCtl list.");

const char*
IoCtlString(
    ULONG IoControlCode
)
{
    ULONG FuncCode = ((IoControlCode >> 2) & 0xFFF) - 100;
    return FuncCode < ARRAYSIZE(IoCtls) ? IoCtls[FuncCode].Name : "UNKNOWN IOCTL";
}

BOOLEAN
try_spinel_datatype_unpack(
    const uint8_t *data_in,
    spinel_size_t data_len,
    const char *pack_format,
    ...
    )
{
    va_list args;
    va_start(args, pack_format);
	spinel_ssize_t packed_len = spinel_datatype_vunpack(data_in, data_len, pack_format, args);
    va_end(args);

    return !(packed_len < 0 || (spinel_size_t)packed_len > data_len);
}

// Handles queries for the current list of Thread interfaces
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtlEnumerateInterfaces(
    _In_reads_bytes_(InBufferLength)
            PVOID           InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG NewOutBufferLength = 0;
    POTLWF_INTERFACE_LIST pInterfaceList = (POTLWF_INTERFACE_LIST)OutBuffer;
    
    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    LogFuncEntry(DRIVER_IOCTL);

    // Make sure to zero out the output first
    RtlZeroMemory(OutBuffer, *OutBufferLength);

    NdisAcquireSpinLock(&FilterListLock);

    // Make sure there is enough space for the first uint16_t
    if (*OutBufferLength < sizeof(uint16_t))
    {
        status = STATUS_BUFFER_TOO_SMALL;
        goto error;
    }

    // Iterate through each interface and build up the list of running interfaces
    for (PLIST_ENTRY Link = FilterModuleList.Flink; Link != &FilterModuleList; Link = Link->Flink)
    {
        PMS_FILTER pFilter = CONTAINING_RECORD(Link, MS_FILTER, FilterModuleLink);
        if (pFilter->State != FilterRunning) continue;

        PGUID pInterfaceGuid = &pInterfaceList->InterfaceGuids[pInterfaceList->cInterfaceGuids];
        pInterfaceList->cInterfaceGuids++;

        NewOutBufferLength =
            FIELD_OFFSET(OTLWF_INTERFACE_LIST, InterfaceGuids) +
            pInterfaceList->cInterfaceGuids * sizeof(GUID);

        if (NewOutBufferLength <= *OutBufferLength)
        {
            *pInterfaceGuid = pFilter->InterfaceGuid;
        }
    }

    if (NewOutBufferLength > *OutBufferLength)
    {
        NewOutBufferLength = sizeof(USHORT);
    }

error:

    NdisReleaseSpinLock(&FilterListLock);

    *OutBufferLength = NewOutBufferLength;

    LogFuncExitNT(DRIVER_IOCTL, status);

    return status;
}

// Handles queries for the details of a specific Thread interface
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtlQueryInterface(
    _In_reads_bytes_(InBufferLength)
            PVOID           InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG    NewOutBufferLength = 0;

    LogFuncEntry(DRIVER_IOCTL);

    // Make sure there is enough space for the first USHORT
    if (InBufferLength < sizeof(GUID) || *OutBufferLength < sizeof(OTLWF_DEVICE))
    {
        status = STATUS_BUFFER_TOO_SMALL;
        goto error;
    }
    
    PGUID pInterfaceGuid = (PGUID)InBuffer;
    POTLWF_DEVICE pDevice = (POTLWF_DEVICE)OutBuffer;

    // Look up the interface
    PMS_FILTER pFilter = otLwfFindAndRefInterface(pInterfaceGuid);
    if (pFilter == NULL)
    {
        status = STATUS_DEVICE_DOES_NOT_EXIST;
        goto error;
    }

    NewOutBufferLength = sizeof(OTLWF_DEVICE);
    pDevice->CompartmentID = pFilter->InterfaceCompartmentID;

    // Release the ref on the interface
    otLwfReleaseInterface(pFilter);

error:

    if (NewOutBufferLength < *OutBufferLength)
    {
        RtlZeroMemory((PUCHAR)OutBuffer + NewOutBufferLength, *OutBufferLength - NewOutBufferLength);
    }

    *OutBufferLength = NewOutBufferLength;

    LogFuncExitNT(DRIVER_IOCTL, status);

    return status;
}

// Handles IOTCLs for OpenThread control
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtlOpenThreadControl(
    _In_ PIRP Irp
    )
{
    NTSTATUS   status = STATUS_PENDING;
    PMS_FILTER pFilter = NULL;

    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    LogFuncEntry(DRIVER_IOCTL);

    if (IrpSp->Parameters.DeviceIoControl.InputBufferLength < sizeof(GUID))
    {
        status = STATUS_INVALID_PARAMETER;
        goto error;
    }

    pFilter = otLwfFindAndRefInterface((PGUID)Irp->AssociatedIrp.SystemBuffer);
    if (pFilter == NULL)
    {
        status = STATUS_DEVICE_DOES_NOT_EXIST;
        goto error;
    }
    
    if (pFilter->MiniportCapabilities.MiniportMode == OT_MP_MODE_RADIO)
    {
        // Pend the Irp for processing on the OpenThread event processing thread
        otLwfEventProcessingIndicateIrp(pFilter, Irp);
    }
    else
    {
        status = otLwfTunIoCtl(pFilter, Irp);
    }

    // Release our ref on the filter
    otLwfReleaseInterface(pFilter);

error:

    // Complete the IRP if we aren't pending (indicates we failed)
    if (status != STATUS_PENDING)
    {
        NT_ASSERT(status != STATUS_SUCCESS);
        RtlZeroMemory(Irp->AssociatedIrp.SystemBuffer, IrpSp->Parameters.DeviceIoControl.OutputBufferLength);
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    LogFuncExitNT(DRIVER_IOCTL, status);

    return status;
}

// Handles Irp for IOTCLs for OpenThread control on the OpenThread thread
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
otLwfCompleteOpenThreadIrp(
    _In_ PMS_FILTER     pFilter,
    _In_ PIRP           Irp
    )
{
    PIO_STACK_LOCATION  IrpSp = IoGetCurrentIrpStackLocation(Irp);

    PUCHAR InBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer + sizeof(GUID);
    PVOID OutBuffer = Irp->AssociatedIrp.SystemBuffer;

    ULONG InBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength - sizeof(GUID);
    ULONG OutBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;

    ULONG OrigOutBufferLength = OutBufferLength;
        
    NTSTATUS status = STATUS_NOT_IMPLEMENTED;
    
    ULONG FuncCode = ((IoControlCode >> 2) & 0xFFF) - 100;
    if (FuncCode < ARRAYSIZE(IoCtls))
    {
        LogVerbose(DRIVER_IOCTL, "Processing Irp=%p, for %s (In:%u,Out:%u)", 
                    Irp, IoCtls[FuncCode].Name, InBufferLength, OutBufferLength);

        if (IoCtls[FuncCode].otFunc)
        {
            status = IoCtls[FuncCode].otFunc(pFilter, InBuffer, InBufferLength, OutBuffer, &OutBufferLength);
        }
        else
        {
            OutBufferLength = 0;
        }

        LogVerbose(DRIVER_IOCTL, "Completing Irp=%p, with %!STATUS! for %s (Out:%u)", 
                    Irp, status, IoCtls[FuncCode].Name, OutBufferLength);
    }
    else
    {
        OutBufferLength = 0;
    }

    // Clear any leftover output buffer
    if (OutBufferLength < OrigOutBufferLength)
    {
        RtlZeroMemory((PUCHAR)OutBuffer + OutBufferLength, OrigOutBufferLength - OutBufferLength);
    }

    // Complete the IRP
    Irp->IoStatus.Information = OutBufferLength;
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

// Handles Irp for IOTCLs for OpenThread control on the OpenThread thread
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfTunIoCtl(
    _In_ PMS_FILTER     pFilter,
    _In_ PIRP           Irp
    )
{
    PIO_STACK_LOCATION  IrpSp = IoGetCurrentIrpStackLocation(Irp);

    PUCHAR InBuffer = (PUCHAR)Irp->AssociatedIrp.SystemBuffer + sizeof(GUID);
    ULONG InBufferLength = IrpSp->Parameters.DeviceIoControl.InputBufferLength - sizeof(GUID);
    ULONG OutBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
        
    NTSTATUS status = STATUS_NOT_IMPLEMENTED;
    
    ULONG FuncCode = ((IoControlCode >> 2) & 0xFFF) - 100;
    if (FuncCode < ARRAYSIZE(IoCtls))
    {
        LogVerbose(DRIVER_IOCTL, "Processing Irp=%p, for %s (In:%u,Out:%u)", 
                    Irp, IoCtls[FuncCode].Name, InBufferLength, OutBufferLength);

        if (IoCtls[FuncCode].tunFunc)
        {
            status = IoCtls[FuncCode].tunFunc(pFilter, Irp, InBuffer, InBufferLength, OutBufferLength);
        }

        if (!NT_SUCCESS(status))
        {
            LogVerbose(DRIVER_IOCTL, "Completing Irp=%p, with %!STATUS! for %s", 
                        Irp, status, IoCtls[FuncCode].Name);
        }
    }

    if (NT_SUCCESS(status))
    {
        status = STATUS_PENDING;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otInterface(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(BOOLEAN))
    {
        BOOLEAN IsEnabled = *(BOOLEAN*)InBuffer;
        if (IsEnabled)
        {
            // Make sure our addresses are in sync
            (void)otLwfInitializeAddresses(pFilter);
            otLwfAddressesUpdated(pFilter);

            status = ThreadErrorToNtstatus(otInterfaceUp(pFilter->otCtx));
        }
        else
        {
            status = ThreadErrorToNtstatus(otInterfaceDown(pFilter->otCtx));
        }
        
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(BOOLEAN))
    {
        *(BOOLEAN*)OutBuffer = otIsInterfaceUp(pFilter->otCtx) ? TRUE : FALSE;
        *OutBufferLength = sizeof(BOOLEAN);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfTunIoCtl_otInterface(
    _In_ PMS_FILTER         pFilter,
    _In_ PIRP               pIrp,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _In_    ULONG           OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(BOOLEAN))
    {
        BOOLEAN IsEnabled = *(BOOLEAN*)InBuffer;
        if (IsEnabled)
        {
            // Make sure our addresses are in sync
            (void)otLwfInitializeAddresses(pFilter);
            otLwfAddressesUpdated(pFilter);
        }

        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                NULL,
                SPINEL_CMD_PROP_VALUE_SET,
                SPINEL_PROP_NET_IF_UP,
                sizeof(BOOLEAN),
                SPINEL_DATATYPE_BOOL_S,
                IsEnabled);
    }
    else if (OutBufferLength >= sizeof(BOOLEAN))
    {
        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                otLwfTunIoCtl_otInterface_Handler,
                SPINEL_CMD_PROP_VALUE_GET,
                SPINEL_PROP_NET_IF_UP,
                0,
                NULL);
    }

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
otLwfTunIoCtl_otInterface_Handler(
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID OutBuffer,
    _Inout_ PULONG OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (Key == SPINEL_PROP_NET_IF_UP)
    {
		BOOLEAN IsEnabled = FALSE;
        if (try_spinel_datatype_unpack(Data, DataLength, SPINEL_DATATYPE_BOOL_S, &IsEnabled))
        {
            *(BOOLEAN*)OutBuffer = IsEnabled;
            *OutBufferLength = sizeof(BOOLEAN);
            status = STATUS_SUCCESS;
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otThread(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(BOOLEAN))
    {
        BOOLEAN IsEnabled = *(BOOLEAN*)InBuffer;
        if (IsEnabled)
        {
            status = ThreadErrorToNtstatus(otThreadStart(pFilter->otCtx));
        }
        else
        {
            status = ThreadErrorToNtstatus(otThreadStop(pFilter->otCtx));
        }
        
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(BOOLEAN))
    {
        *(BOOLEAN*)OutBuffer = (otGetDeviceRole(pFilter->otCtx) > kDeviceRoleDisabled) ? TRUE : FALSE;
        *OutBufferLength = sizeof(BOOLEAN);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfTunIoCtl_otThread(
    _In_ PMS_FILTER         pFilter,
    _In_ PIRP               pIrp,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _In_    ULONG           OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(BOOLEAN))
    {
        BOOLEAN IsEnabled = *(BOOLEAN*)InBuffer;

        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                NULL,
                SPINEL_CMD_PROP_VALUE_SET,
                SPINEL_PROP_NET_STACK_UP,
                sizeof(BOOLEAN),
                SPINEL_DATATYPE_BOOL_S,
                IsEnabled);
    }
    else if (OutBufferLength >= sizeof(BOOLEAN))
    {
        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                otLwfTunIoCtl_otThread_Handler,
                SPINEL_CMD_PROP_VALUE_GET,
                SPINEL_PROP_NET_STACK_UP,
                0,
                NULL);
    }

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
otLwfTunIoCtl_otThread_Handler(
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID OutBuffer,
    _Inout_ PULONG OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (Key == SPINEL_PROP_NET_STACK_UP)
    {
		BOOLEAN IsEnabled = FALSE;
        if (try_spinel_datatype_unpack(Data, DataLength, SPINEL_DATATYPE_BOOL_S, &IsEnabled))
        {
            *(BOOLEAN*)OutBuffer = IsEnabled;
            *OutBufferLength = sizeof(BOOLEAN);
            status = STATUS_SUCCESS;
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otActiveScan(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint32_t) + sizeof(uint16_t))
    {
        uint32_t aScanChannels = *(uint32_t*)InBuffer;
        uint16_t aScanDuration = *(uint16_t*)(InBuffer + sizeof(uint32_t));
        status = ThreadErrorToNtstatus(
            otActiveScan(
                pFilter->otCtx, 
                aScanChannels, 
                aScanDuration, 
                otLwfActiveScanCallback,
                pFilter)
            );
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(BOOLEAN))
    {
        *(BOOLEAN*)OutBuffer = otIsActiveScanInProgress(pFilter->otCtx) ? TRUE : FALSE;
        *OutBufferLength = sizeof(BOOLEAN);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otEnergyScan(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint32_t) + sizeof(uint16_t))
    {
        uint32_t aScanChannels = *(uint32_t*)InBuffer;
        uint16_t aScanDuration = *(uint16_t*)(InBuffer + sizeof(uint32_t));
        status = ThreadErrorToNtstatus(
            otEnergyScan(
                pFilter->otCtx, 
                aScanChannels, 
                aScanDuration, 
                otLwfEnergyScanCallback,
                pFilter)
            );
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(BOOLEAN))
    {
        *(BOOLEAN*)OutBuffer = otIsEnergyScanInProgress(pFilter->otCtx) ? TRUE : FALSE;
        *OutBufferLength = sizeof(BOOLEAN);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otDiscover(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t))
    {
        uint32_t aScanChannels = *(uint32_t*)InBuffer;
        uint16_t aScanDuration = *(uint16_t*)(InBuffer + sizeof(uint32_t));
        uint16_t aPanid = *(uint16_t*)(InBuffer + sizeof(uint32_t) + sizeof(uint16_t));
        status = ThreadErrorToNtstatus(
            otDiscover(
                pFilter->otCtx, 
                aScanChannels, 
                aScanDuration, 
                aPanid,
                otLwfDiscoverCallback,
                pFilter)
            );
    }
    else if (*OutBufferLength >= sizeof(BOOLEAN))
    {
        *(BOOLEAN*)OutBuffer = otIsDiscoverInProgress(pFilter->otCtx) ? TRUE : FALSE;
        *OutBufferLength = sizeof(BOOLEAN);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otChannel(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint8_t))
    {
        uint8_t aChannel = *(uint8_t*)InBuffer;
        status = ThreadErrorToNtstatus(otSetChannel(pFilter->otCtx, aChannel));
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(uint8_t))
    {
        *(uint8_t*)OutBuffer = otGetChannel(pFilter->otCtx);
        *OutBufferLength = sizeof(uint8_t);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfTunIoCtl_otChannel(
    _In_ PMS_FILTER         pFilter,
    _In_ PIRP               pIrp,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _In_    ULONG           OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint8_t))
    {
        uint8_t aChannel = *(uint8_t*)InBuffer;

        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                NULL,
                SPINEL_CMD_PROP_VALUE_SET,
                SPINEL_PROP_PHY_CHAN,
                sizeof(uint8_t),
                SPINEL_DATATYPE_UINT8_S,
                aChannel);
    }
    else if (OutBufferLength >= sizeof(uint8_t))
    {
        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                otLwfTunIoCtl_otChannel_Handler,
                SPINEL_CMD_PROP_VALUE_GET,
                SPINEL_PROP_PHY_CHAN,
                0,
                NULL);
    }

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
otLwfTunIoCtl_otChannel_Handler(
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID OutBuffer,
    _Inout_ PULONG OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (Key == SPINEL_PROP_PHY_CHAN)
    {
		uint8_t aChannel = 0;
        if (try_spinel_datatype_unpack(Data, DataLength, SPINEL_DATATYPE_UINT8_S, &aChannel))
        {
            *(uint8_t*)OutBuffer = aChannel;
            *OutBufferLength = sizeof(uint8_t);
            status = STATUS_SUCCESS;
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otChildTimeout(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint32_t))
    {
        uint32_t aTimeout = *(uint32_t*)InBuffer;
        otSetChildTimeout(pFilter->otCtx, aTimeout);
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(uint32_t))
    {
        *(uint32_t*)OutBuffer = otGetChildTimeout(pFilter->otCtx);
        *OutBufferLength = sizeof(uint32_t);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfTunIoCtl_otChildTimeout(
    _In_ PMS_FILTER         pFilter,
    _In_ PIRP               pIrp,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _In_    ULONG           OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint32_t))
    {
        uint32_t aTimeout = *(uint32_t*)InBuffer;

        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                NULL,
                SPINEL_CMD_PROP_VALUE_SET,
                SPINEL_PROP_THREAD_CHILD_TIMEOUT,
                sizeof(uint32_t),
                SPINEL_DATATYPE_UINT32_S,
                aTimeout);
    }
    else if (OutBufferLength >= sizeof(uint32_t))
    {
        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                otLwfTunIoCtl_otChildTimeout_Handler,
                SPINEL_CMD_PROP_VALUE_GET,
                SPINEL_PROP_THREAD_CHILD_TIMEOUT,
                0,
                NULL);
    }

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
otLwfTunIoCtl_otChildTimeout_Handler(
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID OutBuffer,
    _Inout_ PULONG OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (Key == SPINEL_PROP_THREAD_CHILD_TIMEOUT)
    {
		uint32_t aTimeout = 0;
        if (try_spinel_datatype_unpack(Data, DataLength, SPINEL_DATATYPE_UINT32_S, &aTimeout))
        {
            *(uint32_t*)OutBuffer = aTimeout;
            *OutBufferLength = sizeof(uint32_t);
            status = STATUS_SUCCESS;
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otExtendedAddress(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otExtAddress))
    {
        status = ThreadErrorToNtstatus(otSetExtendedAddress(pFilter->otCtx, (otExtAddress*)InBuffer));
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(otExtAddress))
    {
        memcpy(OutBuffer, otGetExtendedAddress(pFilter->otCtx), sizeof(otExtAddress));
        *OutBufferLength = sizeof(otExtAddress);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfTunIoCtl_otExtendedAddress(
    _In_ PMS_FILTER         pFilter,
    _In_ PIRP               pIrp,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _In_    ULONG           OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otExtAddress))
    {
        const otExtAddress *aExtAddress = (otExtAddress*)InBuffer;

        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                NULL,
                SPINEL_CMD_PROP_VALUE_SET,
                SPINEL_PROP_HWADDR,
                sizeof(otExtAddress),
                SPINEL_DATATYPE_EUI64_S,
                aExtAddress);
    }
    else if (OutBufferLength >= sizeof(otExtAddress))
    {
        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                otLwfTunIoCtl_otExtendedAddress_Handler,
                SPINEL_CMD_PROP_VALUE_GET,
                SPINEL_PROP_HWADDR,
                0,
                NULL);
    }

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
otLwfTunIoCtl_otExtendedAddress_Handler(
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID OutBuffer,
    _Inout_ PULONG OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (Key == SPINEL_PROP_HWADDR)
    {
		otExtAddress *aExtAddress = (otExtAddress*)OutBuffer;
        if (try_spinel_datatype_unpack(Data, DataLength, SPINEL_DATATYPE_EUI64_S, aExtAddress))
        {
            *OutBufferLength = sizeof(otExtAddress);
            status = STATUS_SUCCESS;
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otExtendedPanId(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otExtendedPanId))
    {
        otSetExtendedPanId(pFilter->otCtx, (uint8_t*)InBuffer);
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(otExtendedPanId))
    {
        memcpy(OutBuffer, otGetExtendedPanId(pFilter->otCtx), sizeof(otExtendedPanId));
        *OutBufferLength = sizeof(otExtendedPanId);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfTunIoCtl_otExtendedPanId(
    _In_ PMS_FILTER         pFilter,
    _In_ PIRP               pIrp,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _In_    ULONG           OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otExtendedPanId))
    {
        const otExtendedPanId *aExtPanId = (otExtendedPanId*)InBuffer;

        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                NULL,
                SPINEL_CMD_PROP_VALUE_SET,
                SPINEL_PROP_NET_XPANID,
                sizeof(otExtendedPanId) + sizeof(uint16_t),
                SPINEL_DATATYPE_DATA_S,
                aExtPanId,
                sizeof(otExtendedPanId));
    }
    else if (OutBufferLength >= sizeof(otExtendedPanId))
    {
        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                otLwfTunIoCtl_otExtendedPanId_Handler,
                SPINEL_CMD_PROP_VALUE_GET,
                SPINEL_PROP_NET_XPANID,
                0,
                NULL);
    }

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
otLwfTunIoCtl_otExtendedPanId_Handler(
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID OutBuffer,
    _Inout_ PULONG OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (Key == SPINEL_PROP_NET_XPANID)
    {
		otExtendedPanId *aExtPanId = (otExtendedPanId*)OutBuffer;
        spinel_size_t aExtPanIdLen; 
        if (try_spinel_datatype_unpack(Data, DataLength, SPINEL_DATATYPE_DATA_S, aExtPanId, &aExtPanIdLen) && 
            aExtPanIdLen == sizeof(otExtendedPanId))
        {
            *OutBufferLength = sizeof(otExtendedPanId);
            status = STATUS_SUCCESS;
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otFactoryAssignedIeeeEui64(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    if (*OutBufferLength >= sizeof(otExtAddress))
    {
        otGetFactoryAssignedIeeeEui64(pFilter->otCtx, (otExtAddress*)OutBuffer);
        *OutBufferLength = sizeof(otExtAddress);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otHashMacAddress(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    if (*OutBufferLength >= sizeof(otExtAddress))
    {
        otGetHashMacAddress(pFilter->otCtx, (otExtAddress*)OutBuffer);
        *OutBufferLength = sizeof(otExtAddress);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otLeaderRloc(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    if (*OutBufferLength >= sizeof(otIp6Address))
    {
        status = ThreadErrorToNtstatus(otGetLeaderRloc(pFilter->otCtx, (otIp6Address*)OutBuffer));
        *OutBufferLength = sizeof(otIp6Address);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfTunIoCtl_otLeaderRloc(
    _In_ PMS_FILTER         pFilter,
    _In_ PIRP               pIrp,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _In_    ULONG           OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otIp6Address))
    {
        const otIp6Address *aAddress = (otIp6Address*)InBuffer;

        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                NULL,
                SPINEL_CMD_PROP_VALUE_SET,
                SPINEL_PROP_THREAD_LEADER_ADDR,
                sizeof(otIp6Address),
                SPINEL_DATATYPE_IPv6ADDR_S,
                aAddress);
    }
    else if (OutBufferLength >= sizeof(otIp6Address))
    {
        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                otLwfTunIoCtl_otLeaderRloc_Handler,
                SPINEL_CMD_PROP_VALUE_GET,
                SPINEL_PROP_THREAD_LEADER_ADDR,
                0,
                NULL);
    }

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
otLwfTunIoCtl_otLeaderRloc_Handler(
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID OutBuffer,
    _Inout_ PULONG OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (Key == SPINEL_PROP_THREAD_LEADER_ADDR)
    {
		otIp6Address *aAddress = (otIp6Address*)OutBuffer;
        if (try_spinel_datatype_unpack(Data, DataLength, SPINEL_DATATYPE_IPv6ADDR_S, aAddress))
        {
            *OutBufferLength = sizeof(otIp6Address);
            status = STATUS_SUCCESS;
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otLinkMode(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    static_assert(sizeof(otLinkModeConfig) == 4, "The size of otLinkModeConfig should be 4 bytes");
    if (InBufferLength >= sizeof(otLinkModeConfig))
    {
        status = ThreadErrorToNtstatus(otSetLinkMode(pFilter->otCtx, *(otLinkModeConfig*)InBuffer));
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(otLinkModeConfig))
    {
        *(otLinkModeConfig*)OutBuffer = otGetLinkMode(pFilter->otCtx);
        *OutBufferLength = sizeof(otLinkModeConfig);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

enum
{
    kThreadMode_RxOnWhenIdle        = (1 << 3),
    kThreadMode_SecureDataRequest   = (1 << 2),
    kThreadMode_FullFunctionDevice  = (1 << 1),
    kThreadMode_FullNetworkData     = (1 << 0),
};

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfTunIoCtl_otLinkMode(
    _In_ PMS_FILTER         pFilter,
    _In_ PIRP               pIrp,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _In_    ULONG           OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otLinkModeConfig))
    {
        const otLinkModeConfig* aLinkMode = (otLinkModeConfig*)InBuffer;
        uint8_t numeric_mode = 0;

        if (aLinkMode->mRxOnWhenIdle)       numeric_mode |= kThreadMode_RxOnWhenIdle;
        if (aLinkMode->mSecureDataRequests) numeric_mode |= kThreadMode_SecureDataRequest;
        if (aLinkMode->mDeviceType)         numeric_mode |= kThreadMode_FullFunctionDevice;
        if (aLinkMode->mNetworkData)        numeric_mode |= kThreadMode_FullNetworkData;

        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                NULL,
                SPINEL_CMD_PROP_VALUE_SET,
                SPINEL_PROP_THREAD_MODE,
                sizeof(uint8_t),
                SPINEL_DATATYPE_UINT8_S,
                numeric_mode);
    }
    else if (OutBufferLength >= sizeof(otLinkModeConfig))
    {
        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                otLwfTunIoCtl_otLinkMode_Handler,
                SPINEL_CMD_PROP_VALUE_GET,
                SPINEL_PROP_THREAD_MODE,
                0,
                NULL);
    }

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
otLwfTunIoCtl_otLinkMode_Handler(
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID OutBuffer,
    _Inout_ PULONG OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (Key == SPINEL_PROP_THREAD_MODE)
    {
		uint8_t numeric_mode = 0;
        if (try_spinel_datatype_unpack(Data, DataLength, SPINEL_DATATYPE_UINT8_S, &numeric_mode))
        {
            otLinkModeConfig* aLinkMode = (otLinkModeConfig*)OutBuffer;
            
            aLinkMode->mRxOnWhenIdle = ((numeric_mode & kThreadMode_RxOnWhenIdle) == kThreadMode_RxOnWhenIdle);
            aLinkMode->mSecureDataRequests = ((numeric_mode & kThreadMode_SecureDataRequest) == kThreadMode_SecureDataRequest);
            aLinkMode->mDeviceType = ((numeric_mode & kThreadMode_FullFunctionDevice) == kThreadMode_FullFunctionDevice);
            aLinkMode->mNetworkData = ((numeric_mode & kThreadMode_FullNetworkData) == kThreadMode_FullNetworkData);

            *OutBufferLength = sizeof(otLinkModeConfig);
            status = STATUS_SUCCESS;
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otMasterKey(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otMasterKey) + sizeof(uint8_t))
    {
        uint8_t aKeyLength = *(uint8_t*)(InBuffer + sizeof(otMasterKey));
        status = ThreadErrorToNtstatus(otSetMasterKey(pFilter->otCtx, InBuffer, aKeyLength));
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(otMasterKey) + sizeof(uint8_t))
    {
        uint8_t aKeyLength = 0;
        const uint8_t* aMasterKey = otGetMasterKey(pFilter->otCtx, &aKeyLength);
        memcpy(OutBuffer, aMasterKey, aKeyLength);
        memcpy((PUCHAR)OutBuffer + sizeof(otMasterKey), &aKeyLength, sizeof(uint8_t));
        *OutBufferLength = sizeof(otMasterKey) + sizeof(uint8_t);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfTunIoCtl_otMasterKey(
    _In_ PMS_FILTER         pFilter,
    _In_ PIRP               pIrp,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _In_    ULONG           OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otMasterKey) + sizeof(uint8_t))
    {
        const otMasterKey *aMasterKey = (otMasterKey*)InBuffer;
        spinel_size_t aKeyLength = *(uint8_t*)(InBuffer + sizeof(otMasterKey));

        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                NULL,
                SPINEL_CMD_PROP_VALUE_SET,
                SPINEL_PROP_NET_MASTER_KEY,
                sizeof(otMasterKey) + sizeof(uint16_t),
                SPINEL_DATATYPE_DATA_S,
                aMasterKey,
                aKeyLength);
    }
    else if (OutBufferLength >= sizeof(otMasterKey) + sizeof(uint8_t))
    {
        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                otLwfTunIoCtl_otMasterKey_Handler,
                SPINEL_CMD_PROP_VALUE_GET,
                SPINEL_PROP_NET_MASTER_KEY,
                0,
                NULL);
    }

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
otLwfTunIoCtl_otMasterKey_Handler(
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID OutBuffer,
    _Inout_ PULONG OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (Key == SPINEL_PROP_NET_MASTER_KEY)
    {
		otMasterKey *aMasterKey = (otMasterKey*)OutBuffer;
        spinel_size_t aKeyLength; 
        if (try_spinel_datatype_unpack(Data, DataLength, SPINEL_DATATYPE_DATA_S, aMasterKey, &aKeyLength) && 
            aKeyLength <= sizeof(otMasterKey))
        {
            *(uint8_t*)((PUCHAR)OutBuffer + sizeof(otMasterKey)) = (uint8_t)aKeyLength;
            *OutBufferLength = sizeof(otMasterKey) + sizeof(uint8_t);
            status = STATUS_SUCCESS;
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otMeshLocalEid(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    if (*OutBufferLength >= sizeof(otIp6Address))
    {
        memcpy(OutBuffer,  otGetMeshLocalEid(pFilter->otCtx), sizeof(otIp6Address));
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfTunIoCtl_otMeshLocalEid(
    _In_ PMS_FILTER         pFilter,
    _In_ PIRP               pIrp,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _In_    ULONG           OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    if (OutBufferLength >= sizeof(otIp6Address))
    {
        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                otLwfTunIoCtl_otMeshLocalEid_Handler,
                SPINEL_CMD_PROP_VALUE_GET,
                SPINEL_PROP_IPV6_ML_ADDR,
                0,
                NULL);
    }

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
otLwfTunIoCtl_otMeshLocalEid_Handler(
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID OutBuffer,
    _Inout_ PULONG OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (Key == SPINEL_PROP_IPV6_ML_ADDR)
    {
		otIp6Address *aAddress = (otIp6Address*)OutBuffer;
        if (try_spinel_datatype_unpack(Data, DataLength, SPINEL_DATATYPE_IPv6ADDR_S, aAddress))
        {
            *OutBufferLength = sizeof(otIp6Address);
            status = STATUS_SUCCESS;
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otMeshLocalPrefix(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otMeshLocalPrefix))
    {
        status = ThreadErrorToNtstatus(otSetMeshLocalPrefix(pFilter->otCtx, InBuffer));
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(otMeshLocalPrefix))
    {
        memcpy(OutBuffer, otGetMeshLocalPrefix(pFilter->otCtx), sizeof(otMeshLocalPrefix));
        *OutBufferLength = sizeof(otMeshLocalPrefix);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfTunIoCtl_otMeshLocalPrefix(
    _In_ PMS_FILTER         pFilter,
    _In_ PIRP               pIrp,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _In_    ULONG           OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otMeshLocalPrefix))
    {
        otIp6Address aAddress = {0};
        memcpy(&aAddress, InBuffer, sizeof(otMeshLocalPrefix));

        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                NULL,
                SPINEL_CMD_PROP_VALUE_SET,
                SPINEL_PROP_IPV6_ML_PREFIX,
                sizeof(otIp6Address),
                SPINEL_DATATYPE_IPv6ADDR_S,
                &aAddress);
    }
    else if (OutBufferLength >= sizeof(otMeshLocalPrefix))
    {
        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                otLwfTunIoCtl_otMeshLocalPrefix_Handler,
                SPINEL_CMD_PROP_VALUE_GET,
                SPINEL_PROP_IPV6_ML_PREFIX,
                0,
                NULL);
    }

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
otLwfTunIoCtl_otMeshLocalPrefix_Handler(
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID OutBuffer,
    _Inout_ PULONG OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (Key == SPINEL_PROP_IPV6_ML_PREFIX)
    {
        if (DataLength >= sizeof(otMeshLocalPrefix))
        {
            memcpy(OutBuffer, Data, sizeof(otMeshLocalPrefix));
            *OutBufferLength = sizeof(otMeshLocalPrefix);
            status = STATUS_SUCCESS;
        }
    }
    return status;
}

// otLwfIoCtl_otNetworkDataLeader

// otLwfIoCtl_otNetworkDataLocal

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otNetworkName(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otNetworkName))
    {
        status = ThreadErrorToNtstatus(otSetNetworkName(pFilter->otCtx, (char*)InBuffer));
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(otNetworkName))
    {
        strcpy_s((char*)OutBuffer, sizeof(otNetworkName), otGetNetworkName(pFilter->otCtx));
        *OutBufferLength = sizeof(otNetworkName);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfTunIoCtl_otNetworkName(
    _In_ PMS_FILTER         pFilter,
    _In_ PIRP               pIrp,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _In_    ULONG           OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otNetworkName))
    {
        const otNetworkName *aNetworkName = (otNetworkName*)InBuffer;

        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                NULL,
                SPINEL_CMD_PROP_VALUE_SET,
                SPINEL_PROP_NET_NETWORK_NAME,
                sizeof(otIp6Address),
                SPINEL_DATATYPE_UTF8_S,
                aNetworkName);
    }
    else if (OutBufferLength >= sizeof(otNetworkName))
    {
        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                otLwfTunIoCtl_otNetworkName_Handler,
                SPINEL_CMD_PROP_VALUE_GET,
                SPINEL_PROP_NET_NETWORK_NAME,
                0,
                NULL);
    }

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
otLwfTunIoCtl_otNetworkName_Handler(
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID OutBuffer,
    _Inout_ PULONG OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (Key == SPINEL_PROP_NET_NETWORK_NAME)
    {
		otNetworkName *aNetworkName = (otNetworkName*)OutBuffer;
        if (try_spinel_datatype_unpack(Data, DataLength, SPINEL_DATATYPE_UTF8_S, aNetworkName))
        {
            *OutBufferLength = sizeof(otNetworkName);
            status = STATUS_SUCCESS;
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otPanId(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otPanId))
    {
        status = ThreadErrorToNtstatus(otSetPanId(pFilter->otCtx, *(otPanId*)InBuffer));
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(otPanId))
    {
        *(otPanId*)OutBuffer = otGetPanId(pFilter->otCtx);
        *OutBufferLength = sizeof(otPanId);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfTunIoCtl_otPanId(
    _In_ PMS_FILTER         pFilter,
    _In_ PIRP               pIrp,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _In_    ULONG           OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otPanId))
    {
        otPanId aPanId = *(otPanId*)InBuffer;

        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                NULL,
                SPINEL_CMD_PROP_VALUE_SET,
                SPINEL_PROP_MAC_15_4_PANID,
                sizeof(uint8_t),
                SPINEL_DATATYPE_UINT16_S,
                aPanId);
    }
    else if (OutBufferLength >= sizeof(uint8_t))
    {
        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                otLwfTunIoCtl_otPanId_Handler,
                SPINEL_CMD_PROP_VALUE_GET,
                SPINEL_PROP_MAC_15_4_PANID,
                0,
                NULL);
    }

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
otLwfTunIoCtl_otPanId_Handler(
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID OutBuffer,
    _Inout_ PULONG OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (Key == SPINEL_PROP_MAC_15_4_PANID)
    {
		otPanId aPanId = 0;
        if (try_spinel_datatype_unpack(Data, DataLength, SPINEL_DATATYPE_UINT16_S, &aPanId))
        {
            *(otPanId*)OutBuffer = aPanId;
            *OutBufferLength = sizeof(otPanId);
            status = STATUS_SUCCESS;
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otRouterRollEnabled(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(BOOLEAN))
    {
        otSetRouterRoleEnabled(pFilter->otCtx, *(BOOLEAN*)InBuffer);
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(BOOLEAN))
    {
        *(BOOLEAN*)OutBuffer = otIsRouterRoleEnabled(pFilter->otCtx) ? TRUE : FALSE;
        *OutBufferLength = sizeof(BOOLEAN);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otShortAddress(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    if (*OutBufferLength >= sizeof(otShortAddress))
    {
        *(otShortAddress*)OutBuffer = otGetShortAddress(pFilter->otCtx);
        *OutBufferLength = sizeof(otShortAddress);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

// otLwfIoCtl_otUnicastAddresses

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otActiveDataset(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otOperationalDataset))
    {
        status = ThreadErrorToNtstatus(otSetActiveDataset(pFilter->otCtx, (otOperationalDataset*)InBuffer));
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(otOperationalDataset))
    {
        status = ThreadErrorToNtstatus(otGetActiveDataset(pFilter->otCtx, (otOperationalDataset*)OutBuffer));
        *OutBufferLength = sizeof(otOperationalDataset);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otPendingDataset(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otOperationalDataset))
    {
        status = ThreadErrorToNtstatus(otSetPendingDataset(pFilter->otCtx, (otOperationalDataset*)InBuffer));
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(otOperationalDataset))
    {
        status = ThreadErrorToNtstatus(otGetPendingDataset(pFilter->otCtx, (otOperationalDataset*)OutBuffer));
        *OutBufferLength = sizeof(otOperationalDataset);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otLocalLeaderWeight(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint8_t))
    {
        otSetLocalLeaderWeight(pFilter->otCtx, *(uint8_t*)InBuffer);
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(uint8_t))
    {
        *(uint8_t*)OutBuffer = otGetLeaderWeight(pFilter->otCtx);
        *OutBufferLength = sizeof(uint8_t);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otAddBorderRouter(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    if (InBufferLength >= sizeof(otBorderRouterConfig))
    {
        status = ThreadErrorToNtstatus(otAddBorderRouter(pFilter->otCtx, (otBorderRouterConfig*)InBuffer));
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otRemoveBorderRouter(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    if (InBufferLength >= sizeof(otIp6Prefix))
    {
        status = ThreadErrorToNtstatus(otRemoveBorderRouter(pFilter->otCtx, (otIp6Prefix*)InBuffer));
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otAddExternalRoute(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    if (InBufferLength >= sizeof(otExternalRouteConfig))
    {
        status = ThreadErrorToNtstatus(otAddExternalRoute(pFilter->otCtx, (otExternalRouteConfig*)InBuffer));
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otRemoveExternalRoute(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    if (InBufferLength >= sizeof(otIp6Prefix))
    {
        status = ThreadErrorToNtstatus(otRemoveExternalRoute(pFilter->otCtx, (otIp6Prefix*)InBuffer));
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otSendServerData(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);
    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    status = ThreadErrorToNtstatus(otSendServerData(pFilter->otCtx));

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otContextIdReuseDelay(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint32_t))
    {
        otSetContextIdReuseDelay(pFilter->otCtx, *(uint32_t*)InBuffer);
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(uint32_t))
    {
        *(uint32_t*)OutBuffer = otGetContextIdReuseDelay(pFilter->otCtx);
        status = STATUS_SUCCESS;
        *OutBufferLength = sizeof(uint32_t);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otKeySequenceCounter(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint32_t))
    {
        otSetKeySequenceCounter(pFilter->otCtx, *(uint32_t*)InBuffer);
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(uint32_t))
    {
        *(uint32_t*)OutBuffer = otGetKeySequenceCounter(pFilter->otCtx);
        status = STATUS_SUCCESS;
        *OutBufferLength = sizeof(uint32_t);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otNetworkIdTimeout(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint8_t))
    {
        otSetNetworkIdTimeout(pFilter->otCtx, *(uint8_t*)InBuffer);
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(uint8_t))
    {
        *(uint8_t*)OutBuffer = otGetNetworkIdTimeout(pFilter->otCtx);
        status = STATUS_SUCCESS;
        *OutBufferLength = sizeof(uint8_t);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otRouterUpgradeThreshold(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint8_t))
    {
        otSetRouterUpgradeThreshold(pFilter->otCtx, *(uint8_t*)InBuffer);
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(uint8_t))
    {
        *(uint8_t*)OutBuffer = otGetRouterUpgradeThreshold(pFilter->otCtx);
        status = STATUS_SUCCESS;
        *OutBufferLength = sizeof(uint8_t);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otRouterDowngradeThreshold(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint8_t))
    {
        otSetRouterDowngradeThreshold(pFilter->otCtx, *(uint8_t*)InBuffer);
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(uint8_t))
    {
        *(uint8_t*)OutBuffer = otGetRouterDowngradeThreshold(pFilter->otCtx);
        status = STATUS_SUCCESS;
        *OutBufferLength = sizeof(uint8_t);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otReleaseRouterId(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    if (InBufferLength >= sizeof(uint8_t))
    {
        status = ThreadErrorToNtstatus(otReleaseRouterId(pFilter->otCtx, *(uint8_t*)InBuffer));
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otMacWhitelistEnabled(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(BOOLEAN))
    {
        BOOLEAN aEnabled = *(BOOLEAN*)InBuffer;
        if (aEnabled)
        {
            otEnableMacWhitelist(pFilter->otCtx);
        }
        else
        {
            otDisableMacWhitelist(pFilter->otCtx);
        }
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(BOOLEAN))
    {
        *(BOOLEAN*)OutBuffer = otIsMacWhitelistEnabled(pFilter->otCtx) ? TRUE : FALSE;
        status = STATUS_SUCCESS;
        *OutBufferLength = sizeof(BOOLEAN);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otAddMacWhitelist(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    if (InBufferLength >= sizeof(otExtAddress) + sizeof(int8_t))
    {
        int8_t aRssi = *(int8_t*)(InBuffer + sizeof(otExtAddress));
        status = ThreadErrorToNtstatus(otAddMacWhitelistRssi(pFilter->otCtx, (uint8_t*)InBuffer, aRssi));
    }
    else if (InBufferLength >= sizeof(otExtAddress))
    {
        status = ThreadErrorToNtstatus(otAddMacWhitelist(pFilter->otCtx, (uint8_t*)InBuffer));
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otRemoveMacWhitelist(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    if (InBufferLength >= sizeof(otExtAddress))
    {
        otRemoveMacWhitelist(pFilter->otCtx, (uint8_t*)InBuffer);
        status = STATUS_SUCCESS;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otMacWhitelistEntry(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    if (InBufferLength >= sizeof(uint8_t) && 
        *OutBufferLength >= sizeof(otMacWhitelistEntry))
    {
        status = ThreadErrorToNtstatus(
            otGetMacWhitelistEntry(
                pFilter->otCtx, 
                *(uint8_t*)InBuffer, 
                (otMacWhitelistEntry*)OutBuffer)
            );
        *OutBufferLength = sizeof(otMacWhitelistEntry);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otClearMacWhitelist(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);
    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    otClearMacWhitelist(pFilter->otCtx);

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otDeviceRole(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    if (InBufferLength >= sizeof(uint8_t))
    {
        otDeviceRole role = *(uint8_t*)InBuffer;

        InBufferLength -= sizeof(uint8_t);
        InBuffer = InBuffer + sizeof(uint8_t);

        if (role == kDeviceRoleLeader)
        {
            status = ThreadErrorToNtstatus(
                        otBecomeLeader(pFilter->otCtx)
                        );
        }
        else if (role == kDeviceRoleRouter)
        {
            status = ThreadErrorToNtstatus(
                        otBecomeRouter(pFilter->otCtx)
                        );
        }
        else if (role == kDeviceRoleChild)
        {
            if (InBufferLength >= sizeof(uint8_t))
            {
                status = ThreadErrorToNtstatus(
                            otBecomeChild(pFilter->otCtx, *(uint8_t*)InBuffer)
                            );
            }
        }
        else if (role == kDeviceRoleDetached)
        {
            status = ThreadErrorToNtstatus(
                        otBecomeDetached(pFilter->otCtx)
                        );
        }
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(uint8_t))
    {
        *(uint8_t*)OutBuffer = (uint8_t)otGetDeviceRole(pFilter->otCtx);
        *OutBufferLength = sizeof(uint8_t);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfTunIoCtl_otDeviceRole(
    _In_ PMS_FILTER         pFilter,
    _In_ PIRP               pIrp,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _In_    ULONG           OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint8_t))
    {
        otDeviceRole role = *(uint8_t*)InBuffer;
        uint8_t spinel_role = SPINEL_NET_ROLE_DETACHED;

        switch (role)
        {
        case kDeviceRoleChild:
            spinel_role = SPINEL_NET_ROLE_CHILD;
            break;
        case kDeviceRoleRouter:
            spinel_role = SPINEL_NET_ROLE_ROUTER;
            break;
        case kDeviceRoleLeader:
            spinel_role = SPINEL_NET_ROLE_LEADER;
            break;
        }

        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                NULL,
                SPINEL_CMD_PROP_VALUE_SET,
                SPINEL_PROP_NET_ROLE,
                sizeof(uint8_t),
                SPINEL_DATATYPE_UINT8_S,
                spinel_role);
    }
    else if (OutBufferLength >= sizeof(uint8_t))
    {
        status = 
            otLwfSendTunnelCommandForIrp(
                pFilter,
                pIrp,
                otLwfTunIoCtl_otDeviceRole_Handler,
                SPINEL_CMD_PROP_VALUE_GET,
                SPINEL_PROP_NET_ROLE,
                0,
                NULL);
    }

    return status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
otLwfTunIoCtl_otDeviceRole_Handler(
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID OutBuffer,
    _Inout_ PULONG OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (Key == SPINEL_PROP_NET_ROLE)
    {
		uint8_t spinel_role = 0;
        if (try_spinel_datatype_unpack(Data, DataLength, SPINEL_DATATYPE_UINT8_S, &spinel_role))
        {
            switch (spinel_role)
            {
            default:
            case SPINEL_NET_ROLE_DETACHED:
                *(uint8_t*)OutBuffer = kDeviceRoleDetached;
                break;
            case SPINEL_NET_ROLE_CHILD:
                *(uint8_t*)OutBuffer = kDeviceRoleChild;
                break;
            case SPINEL_NET_ROLE_ROUTER:
                *(uint8_t*)OutBuffer = kDeviceRoleRouter;
                break;
            case SPINEL_NET_ROLE_LEADER:
                *(uint8_t*)OutBuffer = kDeviceRoleLeader;
                break;
            }

            *OutBufferLength = sizeof(uint8_t);
            status = STATUS_SUCCESS;
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otChildInfoById(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    if (InBufferLength >= sizeof(uint16_t) && 
        *OutBufferLength >= sizeof(otChildInfo))
    {
        status = ThreadErrorToNtstatus(
            otGetChildInfoById(
                pFilter->otCtx, 
                *(uint16_t*)InBuffer, 
                (otChildInfo*)OutBuffer)
            );
        *OutBufferLength = sizeof(otChildInfo);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otChildInfoByIndex(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    if (InBufferLength >= sizeof(uint8_t) && 
        *OutBufferLength >= sizeof(otChildInfo))
    {
        status = ThreadErrorToNtstatus(
            otGetChildInfoByIndex(
                pFilter->otCtx, 
                *(uint8_t*)InBuffer, 
                (otChildInfo*)OutBuffer)
            );
        *OutBufferLength = sizeof(otChildInfo);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otEidCacheEntry(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    if (InBufferLength >= sizeof(uint8_t) && 
        *OutBufferLength >= sizeof(otEidCacheEntry))
    {
        status = ThreadErrorToNtstatus(
            otGetEidCacheEntry(
                pFilter->otCtx, 
                *(uint8_t*)InBuffer, 
                (otEidCacheEntry*)OutBuffer)
            );
        *OutBufferLength = sizeof(otEidCacheEntry);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otLeaderData(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    if (*OutBufferLength >= sizeof(otLeaderData))
    {
        status = ThreadErrorToNtstatus(otGetLeaderData(pFilter->otCtx, (otLeaderData*)OutBuffer));
        *OutBufferLength = sizeof(otLeaderData);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otLeaderRouterId(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    if (*OutBufferLength >= sizeof(uint8_t))
    {
        *(uint8_t*)OutBuffer = otGetLeaderRouterId(pFilter->otCtx);
        *OutBufferLength = sizeof(uint8_t);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otLeaderWeight(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    if (*OutBufferLength >= sizeof(uint8_t))
    {
        *(uint8_t*)OutBuffer = otGetLeaderWeight(pFilter->otCtx);
        *OutBufferLength = sizeof(uint8_t);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otNetworkDataVersion(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    if (*OutBufferLength >= sizeof(uint8_t))
    {
        *(uint8_t*)OutBuffer = otGetNetworkDataVersion(pFilter->otCtx);
        *OutBufferLength = sizeof(uint8_t);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otPartitionId(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    if (*OutBufferLength >= sizeof(uint32_t))
    {
        *(uint32_t*)OutBuffer = otGetPartitionId(pFilter->otCtx);
        *OutBufferLength = sizeof(uint32_t);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otRloc16(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    if (*OutBufferLength >= sizeof(uint16_t))
    {
        *(uint16_t*)OutBuffer = otGetRloc16(pFilter->otCtx);
        *OutBufferLength = sizeof(uint16_t);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otRouterIdSequence(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    if (*OutBufferLength >= sizeof(uint8_t))
    {
        *(uint8_t*)OutBuffer = otGetRouterIdSequence(pFilter->otCtx);
        *OutBufferLength = sizeof(uint8_t);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otRouterInfo(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    if (InBufferLength >= sizeof(uint16_t) && 
        *OutBufferLength >= sizeof(otRouterInfo))
    {
        status = ThreadErrorToNtstatus(
            otGetRouterInfo(
                pFilter->otCtx, 
                *(uint16_t*)InBuffer, 
                (otRouterInfo*)OutBuffer)
            );
        *OutBufferLength = sizeof(otRouterInfo);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otStableNetworkDataVersion(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    if (*OutBufferLength >= sizeof(uint8_t))
    {
        *(uint8_t*)OutBuffer = otGetStableNetworkDataVersion(pFilter->otCtx);
        *OutBufferLength = sizeof(uint8_t);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otMacBlacklistEnabled(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(BOOLEAN))
    {
        BOOLEAN aEnabled = *(BOOLEAN*)InBuffer;
        if (aEnabled)
        {
            otEnableMacBlacklist(pFilter->otCtx);
        }
        else
        {
            otDisableMacBlacklist(pFilter->otCtx);
        }
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(BOOLEAN))
    {
        *(BOOLEAN*)OutBuffer = otIsMacBlacklistEnabled(pFilter->otCtx) ? TRUE : FALSE;
        status = STATUS_SUCCESS;
        *OutBufferLength = sizeof(BOOLEAN);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otAddMacBlacklist(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    if (InBufferLength >= sizeof(otExtAddress))
    {
        status = ThreadErrorToNtstatus(otAddMacBlacklist(pFilter->otCtx, (uint8_t*)InBuffer));
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otRemoveMacBlacklist(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    if (InBufferLength >= sizeof(otExtAddress))
    {
        otRemoveMacBlacklist(pFilter->otCtx, (uint8_t*)InBuffer);
        status = STATUS_SUCCESS;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otMacBlacklistEntry(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    if (InBufferLength >= sizeof(uint8_t) && 
        *OutBufferLength >= sizeof(otMacBlacklistEntry))
    {
        status = ThreadErrorToNtstatus(
            otGetMacBlacklistEntry(
                pFilter->otCtx, 
                *(uint8_t*)InBuffer, 
                (otMacBlacklistEntry*)OutBuffer)
            );
        *OutBufferLength = sizeof(otMacBlacklistEntry);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otClearMacBlacklist(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);
    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    otClearMacBlacklist(pFilter->otCtx);

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otMaxTransmitPower(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(int8_t))
    {
        otSetMaxTransmitPower(pFilter->otCtx, *(int8_t*)InBuffer);
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(int8_t))
    {
        *(int8_t*)OutBuffer = otGetMaxTransmitPower(pFilter->otCtx);
        *OutBufferLength = sizeof(int8_t);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otNextOnMeshPrefix(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    if (InBufferLength >= sizeof(BOOLEAN) + sizeof(uint8_t) && 
        *OutBufferLength >= sizeof(uint8_t) + sizeof(otBorderRouterConfig))
    {
        BOOLEAN aLocal = *(BOOLEAN*)InBuffer;
        uint8_t aIterator = *(uint8_t*)(InBuffer + sizeof(BOOLEAN));
        otBorderRouterConfig* aConfig = (otBorderRouterConfig*)((PUCHAR)OutBuffer + sizeof(uint8_t));
        status = ThreadErrorToNtstatus(
            otGetNextOnMeshPrefix(
                pFilter->otCtx, 
                aLocal, 
                &aIterator,
                aConfig)
            );
        *OutBufferLength = sizeof(uint8_t) + sizeof(otBorderRouterConfig);
        if (status == STATUS_SUCCESS)
        {
            *(uint8_t*)OutBuffer = aIterator;
        }
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otPollPeriod(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint32_t))
    {
        otSetPollPeriod(pFilter->otCtx, *(uint32_t*)InBuffer);
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(uint32_t))
    {
        *(uint32_t*)OutBuffer = otGetPollPeriod(pFilter->otCtx);
        *OutBufferLength = sizeof(uint32_t);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otLocalLeaderPartitionId(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint32_t))
    {
        otSetLocalLeaderPartitionId(pFilter->otCtx, *(uint32_t*)InBuffer);
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(uint32_t))
    {
        *(uint32_t*)OutBuffer = otGetLocalLeaderPartitionId(pFilter->otCtx);
        *OutBufferLength = sizeof(uint32_t);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otAssignLinkQuality(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(otExtAddress) + sizeof(uint8_t))
    {
        otSetAssignLinkQuality(
            pFilter->otCtx, 
            (uint8_t*)InBuffer, 
            *(uint8_t*)(InBuffer + sizeof(otExtAddress)));
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (InBufferLength >= sizeof(otExtAddress) &&
            *OutBufferLength >= sizeof(uint8_t))
    {
        status = ThreadErrorToNtstatus(
            otGetAssignLinkQuality(
                pFilter->otCtx, 
                (uint8_t*)InBuffer, 
                (uint8_t*)OutBuffer)
            );
        *OutBufferLength = sizeof(uint32_t);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otPlatformReset(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);
    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    otPlatformReset(pFilter->otCtx);

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otParentInfo(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);
    
    static_assert(sizeof(otRouterInfo) == 20, "The size of otRouterInfo should be 20 bytes");
    if (*OutBufferLength >= sizeof(otRouterInfo))
    {
        status = ThreadErrorToNtstatus(otGetParentInfo(pFilter->otCtx, (otRouterInfo*)OutBuffer));
        *OutBufferLength = sizeof(otRouterInfo);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otSingleton(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    if (*OutBufferLength >= sizeof(BOOLEAN))
    {
        *(BOOLEAN*)OutBuffer = otIsSingleton(pFilter->otCtx) ? TRUE : FALSE;
        *OutBufferLength = sizeof(BOOLEAN);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otMacCounters(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);

    if (*OutBufferLength >= sizeof(otMacCounters))
    {
        memcpy_s(OutBuffer, *OutBufferLength, otGetMacCounters(pFilter->otCtx), sizeof(otMacCounters));
        *OutBufferLength = sizeof(otMacCounters);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}    

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otMaxChildren(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint8_t))
    {
        otSetMaxAllowedChildren(pFilter->otCtx, *(uint8_t*)InBuffer);
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(uint8_t))
    {
        *(uint8_t*)OutBuffer = otGetMaxAllowedChildren(pFilter->otCtx);
        *OutBufferLength = sizeof(uint8_t);
        status = STATUS_SUCCESS;
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otCommissionerStart(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{    
    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);
    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    return ThreadErrorToNtstatus(otCommissionerStart(pFilter->otCtx));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otCommissionerStop(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);
    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    status = ThreadErrorToNtstatus(otCommissionerStop(pFilter->otCtx));

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otJoinerStart(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    
    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    if (InBufferLength >= sizeof(otCommissionConfig))
    {
        otCommissionConfig *aConfig = (otCommissionConfig*)InBuffer;
        status = ThreadErrorToNtstatus(otJoinerStart(
            pFilter->otCtx, (const char*)aConfig->PSKd, (const char*)aConfig->ProvisioningUrl));
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otJoinerStop(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(InBuffer);
    UNREFERENCED_PARAMETER(InBufferLength);
    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    status = ThreadErrorToNtstatus(otJoinerStop(pFilter->otCtx));

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otCommissionerPanIdQuery(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    *OutBufferLength = 0;
    UNREFERENCED_PARAMETER(OutBuffer);

    if (InBufferLength >= sizeof(uint16_t) + sizeof(uint32_t) + sizeof(otIp6Address))
    {
        uint16_t aPanId = *(uint16_t*)InBuffer;
        uint32_t aChannelMask = *(uint32_t*)(InBuffer + sizeof(uint16_t));
        const otIp6Address *aAddress = (otIp6Address*)(InBuffer + sizeof(uint16_t) + sizeof(uint32_t));

        status = ThreadErrorToNtstatus(
            otCommissionerPanIdQuery(
                pFilter->otCtx, 
                aPanId, 
                aChannelMask,
                aAddress,
                otLwfCommissionerPanIdConflictCallback,
                pFilter)
            );
    }

    return status;
}    

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otCommissionerEnergyScan(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    *OutBufferLength = 0;
    UNREFERENCED_PARAMETER(OutBuffer);

    if (InBufferLength >= sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(otIp6Address))
    {
        uint32_t aChannelMask = *(uint32_t*)InBuffer;
        uint8_t aCount = *(uint8_t*)(InBuffer + sizeof(uint32_t));
        uint16_t aPeriod = *(uint16_t*)(InBuffer + sizeof(uint32_t) + sizeof(uint8_t));
        uint16_t aScanDuration = *(uint16_t*)(InBuffer + sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint16_t));
        const otIp6Address *aAddress = (otIp6Address*)(InBuffer + sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t));

        status = ThreadErrorToNtstatus(
            otCommissionerEnergyScan(
                pFilter->otCtx,
                aChannelMask,
                aCount,
                aPeriod,
                aScanDuration,
                aAddress,
                otLwfCommissionerEnergyReportCallback,
                pFilter)
            );
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otRouterSelectionJitter(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint8_t))
    {
        otSetRouterSelectionJitter(pFilter->otCtx, *(uint8_t*)InBuffer);
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(uint8_t))
    {
        *(uint8_t*)OutBuffer = otGetRouterSelectionJitter(pFilter->otCtx);
        status = STATUS_SUCCESS;
        *OutBufferLength = sizeof(uint8_t);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otJoinerUdpPort(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint16_t))
    {
        otSetJoinerUdpPort(pFilter->otCtx, *(uint16_t*)InBuffer);
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(uint16_t))
    {
        *(uint16_t*)OutBuffer = otGetJoinerUdpPort(pFilter->otCtx);
        status = STATUS_SUCCESS;
        *OutBufferLength = sizeof(uint16_t);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}    

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otSendDiagnosticGet(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    *OutBufferLength = 0;
    UNREFERENCED_PARAMETER(OutBuffer);

    if (InBufferLength >= sizeof(otIp6Address) + sizeof(uint8_t))
    {
        const otIp6Address *aAddress = (otIp6Address*)InBuffer;
        uint8_t aCount = *(uint8_t*)(InBuffer + sizeof(otIp6Address));
        PUCHAR aTlvTypes = InBuffer + sizeof(otIp6Address) + sizeof(uint8_t);

        if (InBufferLength >= sizeof(otIp6Address) + sizeof(uint8_t) + aCount)
        {
            status = ThreadErrorToNtstatus(
                otSendDiagnosticGet(
                    pFilter->otCtx,
                    aAddress,
                    aTlvTypes,
                    aCount)
                );
        }
    }

    return status;
}   

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otSendDiagnosticReset(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    *OutBufferLength = 0;
    UNREFERENCED_PARAMETER(OutBuffer);

    if (InBufferLength >= sizeof(otIp6Address) + sizeof(uint8_t))
    {
        const otIp6Address *aAddress = (otIp6Address*)InBuffer;
        uint8_t aCount = *(uint8_t*)(InBuffer + sizeof(otIp6Address));
        PUCHAR aTlvTypes = InBuffer + sizeof(otIp6Address) + sizeof(uint8_t);

        if (InBufferLength >= sizeof(otIp6Address) + sizeof(uint8_t) + aCount)
        {
            status = ThreadErrorToNtstatus(
                otSendDiagnosticGet(
                    pFilter->otCtx,
                    aAddress,
                    aTlvTypes,
                    aCount)
                );
        }
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otCommissionerAddJoiner(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    
    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    if (InBufferLength >= sizeof(uint8_t) + sizeof(otExtAddress))
    {
        const ULONG aPSKdBufferLength = InBufferLength - sizeof(uint8_t) - sizeof(otExtAddress);

        if (aPSKdBufferLength <= OPENTHREAD_PSK_MAX_LENGTH + 1)
        {
            uint8_t aExtAddressValid = *(uint8_t*)InBuffer;
            const otExtAddress *aExtAddress = aExtAddressValid == 0 ? NULL : (otExtAddress*)(InBuffer + sizeof(uint8_t));
            char *aPSKd = (char*)(InBuffer + sizeof(uint8_t) + sizeof(otExtAddress));

            // Ensure aPSKd is NULL terminated in the buffer
            if (strnlen(aPSKd, aPSKdBufferLength) < aPSKdBufferLength)
            {
                status = ThreadErrorToNtstatus(otCommissionerAddJoiner(
                    pFilter->otCtx, aExtAddress, aPSKd));
            }
        }
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otCommissionerRemoveJoiner(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    
    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    if (InBufferLength >= sizeof(uint8_t) + sizeof(otExtAddress))
    {
        uint8_t aExtAddressValid = *(uint8_t*)InBuffer;
        const otExtAddress *aExtAddress = aExtAddressValid == 0 ? NULL : (otExtAddress*)(InBuffer + sizeof(uint8_t));
        status = ThreadErrorToNtstatus(otCommissionerRemoveJoiner(
            pFilter->otCtx, aExtAddress));
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otCommissionerProvisioningUrl(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    
    UNREFERENCED_PARAMETER(OutBuffer);
    *OutBufferLength = 0;
    
    if (InBufferLength <= OPENTHREAD_PROV_URL_MAX_LENGTH + 1)
    {
        char *aProvisioningUrl = InBufferLength > 1 ? (char*)InBuffer : NULL;

        // Ensure aProvisioningUrl is empty or NULL terminated in the buffer
        if (aProvisioningUrl == NULL ||
            strnlen(aProvisioningUrl, InBufferLength) < InBufferLength)
        {
            status = ThreadErrorToNtstatus(otCommissionerSetProvisioningUrl(
                pFilter->otCtx, aProvisioningUrl));
        }
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otCommissionerAnnounceBegin(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    *OutBufferLength = 0;
    UNREFERENCED_PARAMETER(OutBuffer);

    if (InBufferLength >= sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint16_t) + sizeof(otIp6Address))
    {
        uint32_t aChannelMask = *(uint32_t*)InBuffer;
        uint8_t aCount = *(uint8_t*)(InBuffer + sizeof(uint32_t));
        uint16_t aPeriod = *(uint16_t*)(InBuffer + sizeof(uint32_t) + sizeof(uint8_t));
        const otIp6Address *aAddress = (otIp6Address*)(InBuffer + sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint16_t));

        if (InBufferLength >= sizeof(otIp6Address) + sizeof(uint8_t) + aCount)
        {
            status = ThreadErrorToNtstatus(
                otCommissionerAnnounceBegin(
                    pFilter->otCtx,
                    aChannelMask,
                    aCount,
                    aPeriod,
                    aAddress)
                );
        }
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otSendActiveGet(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    *OutBufferLength = 0;
    UNREFERENCED_PARAMETER(OutBuffer);

    if (InBufferLength >= sizeof(uint8_t))
    {
        uint8_t aLength = *(uint8_t*)InBuffer;
        PUCHAR aTlvTypes = aLength == 0 ? NULL : InBuffer + sizeof(uint8_t);

        if (InBufferLength >= sizeof(uint8_t) + aLength)
        {
            status = ThreadErrorToNtstatus(
                otSendActiveGet(
                    pFilter->otCtx,
                    aTlvTypes,
                    aLength)
                );
        }
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otSendActiveSet(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    *OutBufferLength = 0;
    UNREFERENCED_PARAMETER(OutBuffer);

    if (InBufferLength >= sizeof(otOperationalDataset) + sizeof(uint8_t))
    {
        const otOperationalDataset *aDataset = (otOperationalDataset*)InBuffer;
        uint8_t aLength = *(uint8_t*)(InBuffer + sizeof(otOperationalDataset));
        PUCHAR aTlvTypes = aLength == 0 ? NULL : InBuffer + sizeof(otOperationalDataset) + sizeof(uint8_t);

        if (InBufferLength >= sizeof(otOperationalDataset) + sizeof(uint8_t) + aLength)
        {
            status = ThreadErrorToNtstatus(
                otSendActiveSet(
                    pFilter->otCtx,
                    aDataset,
                    aTlvTypes,
                    aLength)
                );
        }
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otSendPendingGet(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    *OutBufferLength = 0;
    UNREFERENCED_PARAMETER(OutBuffer);

    if (InBufferLength >= sizeof(uint8_t))
    {
        uint8_t aLength = *(uint8_t*)InBuffer;
        PUCHAR aTlvTypes = aLength == 0 ? NULL : InBuffer + sizeof(uint8_t);

        if (InBufferLength >= sizeof(uint8_t) + aLength)
        {
            status = ThreadErrorToNtstatus(
                otSendPendingGet(
                    pFilter->otCtx,
                    aTlvTypes,
                    aLength)
                );
        }
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otSendPendingSet(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    *OutBufferLength = 0;
    UNREFERENCED_PARAMETER(OutBuffer);

    if (InBufferLength >= sizeof(otOperationalDataset) + sizeof(uint8_t))
    {
        const otOperationalDataset *aDataset = (otOperationalDataset*)InBuffer;
        uint8_t aLength = *(uint8_t*)(InBuffer + sizeof(otOperationalDataset));
        PUCHAR aTlvTypes = aLength == 0 ? NULL : InBuffer + sizeof(otOperationalDataset) + sizeof(uint8_t);

        if (InBufferLength >= sizeof(otOperationalDataset) + sizeof(uint8_t) + aLength)
        {
            status = ThreadErrorToNtstatus(
                otSendPendingSet(
                    pFilter->otCtx,
                    aDataset,
                    aTlvTypes,
                    aLength)
                );
        }
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otSendMgmtCommissionerGet(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    *OutBufferLength = 0;
    UNREFERENCED_PARAMETER(OutBuffer);

    if (InBufferLength >= sizeof(uint8_t))
    {
        uint8_t aLength = *(uint8_t*)InBuffer;
        PUCHAR aTlvs = aLength == 0 ? NULL : InBuffer + sizeof(uint8_t);

        if (InBufferLength >= sizeof(uint8_t) + aLength)
        {
            status = ThreadErrorToNtstatus(
                otSendMgmtCommissionerGet(
                    pFilter->otCtx,
                    aTlvs,
                    aLength)
                );
        }
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otSendMgmtCommissionerSet(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    
    *OutBufferLength = 0;
    UNREFERENCED_PARAMETER(OutBuffer);

    if (InBufferLength >= sizeof(otCommissioningDataset) + sizeof(uint8_t))
    {
        const otCommissioningDataset *aDataset = (otCommissioningDataset*)InBuffer;
        uint8_t aLength = *(uint8_t*)(InBuffer + sizeof(otCommissioningDataset));
        PUCHAR aTlvs = aLength == 0 ? NULL : InBuffer + sizeof(otCommissioningDataset) + sizeof(uint8_t);

        if (InBufferLength >= sizeof(otCommissioningDataset) + sizeof(uint8_t) + aLength)
        {
            status = ThreadErrorToNtstatus(
                otSendMgmtCommissionerSet(
                    pFilter->otCtx,
                    aDataset,
                    aTlvs,
                    aLength)
                );
        }
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfIoCtl_otKeySwitchGuardtime(
    _In_ PMS_FILTER         pFilter,
    _In_reads_bytes_(InBufferLength)
            PUCHAR          InBuffer,
    _In_    ULONG           InBufferLength,
    _Out_writes_bytes_(*OutBufferLength)
            PVOID           OutBuffer,
    _Inout_ PULONG          OutBufferLength
    )
{
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (InBufferLength >= sizeof(uint32_t))
    {
        otSetKeySwitchGuardTime(pFilter->otCtx, *(uint32_t*)InBuffer);
        status = STATUS_SUCCESS;
        *OutBufferLength = 0;
    }
    else if (*OutBufferLength >= sizeof(uint32_t))
    {
        *(uint32_t*)OutBuffer = otGetKeySwitchGuardTime(pFilter->otCtx);
        status = STATUS_SUCCESS;
        *OutBufferLength = sizeof(uint32_t);
    }
    else
    {
        *OutBufferLength = 0;
    }

    return status;
}
