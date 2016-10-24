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

/**
 * @file
 * @brief
 *  This file implements the Tunnel mode (Thread Miniport) functions required for the OpenThread library.
 */

#include "precomp.h"
#include "tunnel.tmh"

ThreadError
SpinelStatusToThreadError(
    spinel_status_t error
    )
{
    ThreadError ret;

    switch (error)
    {
    case SPINEL_STATUS_OK:
        ret = kThreadError_None;
        break;

    case SPINEL_STATUS_FAILURE:
        ret = kThreadError_Failed;
        break;

    case SPINEL_STATUS_DROPPED:
        ret = kThreadError_Drop;
        break;

    case SPINEL_STATUS_NOMEM:
        ret = kThreadError_NoBufs;
        break;

    case SPINEL_STATUS_BUSY:
        ret = kThreadError_Busy;
        break;

    case SPINEL_STATUS_PARSE_ERROR:
        ret = kThreadError_Parse;
        break;

    case SPINEL_STATUS_INVALID_ARGUMENT:
        ret = kThreadError_InvalidArgs;
        break;

    case SPINEL_STATUS_UNIMPLEMENTED:
        ret = kThreadError_NotImplemented;
        break;

    case SPINEL_STATUS_INVALID_STATE:
        ret = kThreadError_InvalidState;
        break;

    case SPINEL_STATUS_NO_ACK:
        ret = kThreadError_NoAck;
        break;

    case SPINEL_STATUS_CCA_FAILURE:
        ret = kThreadError_ChannelAccessFailure;
        break;

    case SPINEL_STATUS_ALREADY:
        ret = kThreadError_Already;
        break;

    case SPINEL_STATUS_ITEM_NOT_FOUND:
        ret = kThreadError_NotFound;
        break;

    default:
        if (error >= SPINEL_STATUS_STACK_NATIVE__BEGIN && error <= SPINEL_STATUS_STACK_NATIVE__END)
        {
            ret = (ThreadError)(error - SPINEL_STATUS_STACK_NATIVE__BEGIN);
        }
        else
        {
            ret = kThreadError_Failed;
        }
        break;
    }

    return ret;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NDIS_STATUS 
otLwfInitializeTunnelMode(
    _In_ PMS_FILTER pFilter
    )
{
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
    uint32_t InterfaceType = 0;

    LogFuncEntry(DRIVER_DEFAULT);

    pFilter->tunTIDsInUse = 0;
    pFilter->tunNextTID = 1;
    
    NdisAllocateSpinLock(&pFilter->tunCommandLock);
    InitializeListHead(&pFilter->tunCommandHandlers);

    // Query the interface type to make sure it is a Thread device
    Status = otLwfGetTunProp(pFilter, SPINEL_PROP_INTERFACE_TYPE, SPINEL_DATATYPE_UINT_PACKED_S, &InterfaceType);
    if (!NT_SUCCESS(Status))
    {
        LogError(DRIVER_DEFAULT, "Failed to query SPINEL_PROP_INTERFACE_TYPE, %!STATUS!", Status);
        goto error;
    }
    if (InterfaceType != SPINEL_PROTOCOL_TYPE_THREAD)
    {
        Status = STATUS_NOT_SUPPORTED;
        LogError(DRIVER_DEFAULT, "SPINEL_PROP_INTERFACE_TYPE is invalid, %d", InterfaceType);
        goto error;
    }

    // TODO - Query other values and capabilities

error:

    if (!NT_SUCCESS(Status))
    {
        otLwfUninitializeTunnelMode(pFilter);
    }

    LogFuncExitNDIS(DRIVER_DEFAULT, Status);

    return Status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void 
otLwfUninitializeTunnelMode(
    _In_ PMS_FILTER pFilter
    )
{
    LogFuncEntry(DRIVER_DEFAULT);
    UNREFERENCED_PARAMETER(pFilter);
    // TODO - Clean up command handlers
    LogFuncExit(DRIVER_DEFAULT);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void 
otLwfProcessSpinelValueIs(
    _In_ PMS_FILTER pFilter,
    _In_ BOOLEAN DispatchLevel,
    _In_ spinel_prop_key_t key,
    _In_reads_bytes_(value_data_len) const uint8_t* value_data_ptr,
    _In_ spinel_size_t value_data_len
    )
{
    uint32_t aNotifFlags = 0;

    LogFuncEntryMsg(DRIVER_DEFAULT, "[%p] received Value for %s", pFilter, spinel_prop_key_to_cstr(key));

    if (key == SPINEL_PROP_LAST_STATUS) 
    {
        spinel_status_t status = SPINEL_STATUS_OK;
        spinel_datatype_unpack(value_data_ptr, value_data_len, "i", &status);

        if ((status >= SPINEL_STATUS_RESET__BEGIN) && (status <= SPINEL_STATUS_RESET__END)) 
        {
            LogInfo(DRIVER_DEFAULT, "Interface %!GUID! was reset.", &pFilter->InterfaceGuid);
            // TODO - Handle reset
        }
    } 
    else if (key == SPINEL_PROP_NET_ROLE) 
    {
        uint8_t value;
        spinel_datatype_unpack(value_data_ptr, value_data_len, SPINEL_DATATYPE_UINT8_S, &value);

        LogInfo(DRIVER_DEFAULT, "Interface %!GUID! new spinel role: %u", &pFilter->InterfaceGuid, value);

        // Make sure we are in the correct media connect state
        otLwfIndicateLinkState(
            pFilter, 
            value > SPINEL_NET_ROLE_DETACHED ? 
                MediaConnectStateConnected : 
                MediaConnectStateDisconnected);

        // Set flag to indicate we should send a notification
        aNotifFlags = OT_NET_ROLE;
    } 
    else if (key == SPINEL_PROP_IPV6_LL_ADDR) 
    {
        // Set flag to indicate we should send a notification
        aNotifFlags = OT_IP6_LL_ADDR_CHANGED;
    }
    else if (key == SPINEL_PROP_IPV6_ML_ADDR) 
    {
        // Set flag to indicate we should send a notification
        aNotifFlags = OT_IP6_ML_ADDR_CHANGED;
    }
    else if (key == SPINEL_PROP_NET_PARTITION_ID) 
    {
        // Set flag to indicate we should send a notification
        aNotifFlags = OT_NET_PARTITION_ID;
    }
    else if (key == SPINEL_PROP_NET_KEY_SEQUENCE_COUNTER) 
    {
        // Set flag to indicate we should send a notification
        aNotifFlags = OT_NET_KEY_SEQUENCE_COUNTER;
    }
    else if (key == SPINEL_PROP_IPV6_ADDRESS_TABLE) 
    {
        // TODO - Update cached addresses
        // TODO - Send notification
    } 
    else if (key == SPINEL_PROP_THREAD_CHILD_TABLE) 
    {
        // TODO - Update cached children
        // TODO - Send notification
    } 
    else if (key == SPINEL_PROP_THREAD_ON_MESH_NETS) 
    {
        // TODO - Slaac

        // Set flag to indicate we should send a notification
        aNotifFlags = OT_THREAD_NETDATA_UPDATED;
    } 
    else if ((key == SPINEL_PROP_STREAM_NET) || (key == SPINEL_PROP_STREAM_NET_INSECURE)) 
    {
        const uint8_t* frame_ptr = NULL;
        UINT frame_len = 0;
        spinel_ssize_t ret;

        ret = spinel_datatype_unpack(
            value_data_ptr,
            value_data_len,
            SPINEL_DATATYPE_DATA_S SPINEL_DATATYPE_DATA_S,
            &frame_ptr,
            &frame_len,
            NULL,
            NULL);

        NT_ASSERT(ret > 0);
        if (ret > 0) 
        {
            otLwfProcessSpinelIPv6Packet(
                pFilter, 
                DispatchLevel,
                (SPINEL_PROP_STREAM_NET_INSECURE == key) ? FALSE : TRUE,
                frame_ptr,
                frame_len);
        }
    }
    else if (key == SPINEL_PROP_MAC_SCAN_STATE) 
    {
        // TODO - If pending scan, send notification of completion
    } 
    else if (key == SPINEL_PROP_STREAM_RAW) 
    {
        // May be used in the future
    } 
    else if (key == SPINEL_PROP_STREAM_DEBUG) 
    {
        // TODO - Log
    } 

    // Send notification
    if (aNotifFlags != 0)
    {
        PFILTER_NOTIFICATION_ENTRY NotifEntry = FILTER_ALLOC_NOTIF(pFilter);
        if (NotifEntry)
        {
            RtlZeroMemory(NotifEntry, sizeof(FILTER_NOTIFICATION_ENTRY));
            NotifEntry->Notif.InterfaceGuid = pFilter->InterfaceGuid;
            NotifEntry->Notif.NotifType = OTLWF_NOTIF_STATE_CHANGE;
            NotifEntry->Notif.StateChangePayload.Flags = aNotifFlags;

            otLwfIndicateNotification(NotifEntry);
        }
    }

    LogFuncExit(DRIVER_DEFAULT);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void 
otLwfProcessSpinelValueInserted(
    _In_ PMS_FILTER pFilter,
    _In_ BOOLEAN DispatchLevel,
    _In_ spinel_prop_key_t key,
    _In_reads_bytes_(value_data_len) const uint8_t* value_data_ptr,
    _In_ spinel_size_t value_data_len
    )
{
    LogFuncEntryMsg(DRIVER_DEFAULT, "[%p] received Value Inserted for %s", pFilter, spinel_prop_key_to_cstr(key));

    UNREFERENCED_PARAMETER(pFilter);
    UNREFERENCED_PARAMETER(DispatchLevel);
    UNREFERENCED_PARAMETER(value_data_ptr);
    UNREFERENCED_PARAMETER(value_data_len);

    if (key == SPINEL_PROP_MAC_SCAN_BEACON) 
    {
        PFILTER_NOTIFICATION_ENTRY NotifEntry = FILTER_ALLOC_NOTIF(pFilter);
        if (NotifEntry)
        {
            RtlZeroMemory(NotifEntry, sizeof(FILTER_NOTIFICATION_ENTRY));
            NotifEntry->Notif.InterfaceGuid = pFilter->InterfaceGuid;
            NotifEntry->Notif.NotifType = OTLWF_NOTIF_ACTIVE_SCAN;
            NotifEntry->Notif.ActiveScanPayload.Valid = TRUE;

            unsigned int xpanid_len = 0;
            
            //chan,rssi,(laddr,saddr,panid,lqi),(proto,flags,networkid,xpanid) [CcT(ESSC)T(iCUD.).]
            if (try_spinel_datatype_unpack(
                    value_data_ptr, 
                    value_data_len, 
                    "CcT(ESSC.)T(iCUD.).",
                    &NotifEntry->Notif.ActiveScanPayload.Results.mChannel,
                    &NotifEntry->Notif.ActiveScanPayload.Results.mRssi,
                    &NotifEntry->Notif.ActiveScanPayload.Results.mExtAddress.m8,
                    NULL, // saddr (don't care)
                    &NotifEntry->Notif.ActiveScanPayload.Results.mPanId,
                    &NotifEntry->Notif.ActiveScanPayload.Results.mLqi,
                    NULL, // proto (don't care)
                    NULL, // flags (don't care)
                    &NotifEntry->Notif.ActiveScanPayload.Results.mNetworkName.m8,
                    &NotifEntry->Notif.ActiveScanPayload.Results.mExtendedPanId.m8,
                    &xpanid_len
                ) &&
                xpanid_len == OT_EXT_PAN_ID_SIZE)
            {
                otLwfIndicateNotification(NotifEntry);
            }
            else
            {
                FILTER_FREE_MEM(NotifEntry);
            }
        }
    } 
    else if (key == SPINEL_PROP_MAC_ENERGY_SCAN_RESULT) 
    {
        PFILTER_NOTIFICATION_ENTRY NotifEntry = FILTER_ALLOC_NOTIF(pFilter);
        if (NotifEntry)
        {
            RtlZeroMemory(NotifEntry, sizeof(FILTER_NOTIFICATION_ENTRY));
            NotifEntry->Notif.InterfaceGuid = pFilter->InterfaceGuid;
            NotifEntry->Notif.NotifType = OTLWF_NOTIF_ENERGY_SCAN;
            NotifEntry->Notif.EnergyScanPayload.Valid = TRUE;
            
            if (try_spinel_datatype_unpack(
                    value_data_ptr, 
                    value_data_len, 
                    "Cc",
                    &NotifEntry->Notif.EnergyScanPayload.Results.mChannel,
                    &NotifEntry->Notif.EnergyScanPayload.Results.mMaxRssi
                ))
            {
                otLwfIndicateNotification(NotifEntry);
            }
            else
            {
                FILTER_FREE_MEM(NotifEntry);
            }
        }
    } 

    LogFuncExit(DRIVER_DEFAULT);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void 
otLwfProcessSpinelCommand(
    _In_ PMS_FILTER pFilter,
    _In_ BOOLEAN DispatchLevel,
    _In_ UINT command,
    _In_reads_bytes_(cmd_data_len) const uint8_t* cmd_data_ptr,
    _In_ spinel_size_t cmd_data_len
    )
{
    uint8_t Header;
    spinel_prop_key_t key;
    uint8_t* value_data_ptr = NULL;
    spinel_size_t value_data_len = 0;

    // Make sure it's an expected command
    if (command < SPINEL_CMD_PROP_VALUE_IS || command > SPINEL_CMD_PROP_VALUE_REMOVED)
    {
        LogVerbose(DRIVER_DEFAULT, "Recieved unhandled command, %u", command);
        return;
    }

    // Decode the key and data
    if (spinel_datatype_unpack(cmd_data_ptr, cmd_data_len, "CiiD", &Header, NULL, &key, &value_data_ptr, &value_data_len) == -1)
    {
        LogVerbose(DRIVER_DEFAULT, "Failed to unpack command key & data");
        return;
    }

    if (SPINEL_HEADER_GET_TID(Header) == 0)
    {
        // If this is a 'Value Is' command, process it for notification of state changes.
        if (command == SPINEL_CMD_PROP_VALUE_IS)
        {
            otLwfProcessSpinelValueIs(pFilter, DispatchLevel, key, value_data_ptr, value_data_len);
        }
        else if (command == SPINEL_CMD_PROP_VALUE_INSERTED)
        {
            otLwfProcessSpinelValueInserted(pFilter, DispatchLevel, key, value_data_ptr, value_data_len);
        }
    }
    // If there was a transaction ID, then look for the corresponding command handler
    else
    {
        PLIST_ENTRY Link;
        SPINEL_CMD_HANDLER_ENTRY* Handler = NULL;

        FILTER_ACQUIRE_LOCK(&pFilter->tunCommandLock, DispatchLevel);

        // Search for matching handlers for this command
        Link = pFilter->tunCommandHandlers.Flink;
        while (Link != &pFilter->tunCommandHandlers)
        {
            SPINEL_CMD_HANDLER_ENTRY* pEntry = CONTAINING_RECORD(Link, SPINEL_CMD_HANDLER_ENTRY, Link);
            Link = Link->Flink;

            if (SPINEL_HEADER_GET_TID(Header) == pEntry->TransactionId)
            {
                // Remove from the main list
                RemoveEntryList(&pEntry->Link);

                Handler = pEntry;

                // Remove the transaction ID from the 'in use' bit field
                pFilter->tunTIDsInUse &= ~(1 << pEntry->TransactionId);

                break;
            }
        }

        FILTER_RELEASE_LOCK(&pFilter->tunCommandLock, DispatchLevel);

        // TODO - Set event

        // Process the handler we found, outside the lock
        if (Handler)
        {        
            // Call the handler function
            Handler->Handler(pFilter, Handler->Context, command, key, value_data_ptr, value_data_len);

            // Free the entry
            FILTER_FREE_MEM(Handler);
        }
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void 
otLwfReceiveTunnelPacket(
    _In_ PMS_FILTER pFilter,
    _In_ BOOLEAN DispatchLevel,
    _In_reads_bytes_(BufferLength) const PUCHAR Buffer,
    _In_ ULONG BufferLength
    )
{
    uint8_t Header;
    UINT Command;

    // Unpack the header from the buffer
    if (spinel_datatype_unpack(Buffer, BufferLength, "Ci", &Header, &Command) <= 0)
    {
        LogVerbose(DRIVER_DEFAULT, "Failed to unpack header and command");
        return;
    }

    // Validate the header
    if ((Header & SPINEL_HEADER_FLAG) != SPINEL_HEADER_FLAG) 
    {
        LogVerbose(DRIVER_DEFAULT, "Recieved unrecognized frame, header=0x%x", Header);
        return;
    }
    
    // We only support IID zero for now
    if (SPINEL_HEADER_GET_IID(Header) != 0) 
    {
        LogVerbose(DRIVER_DEFAULT, "Recieved unsupported IID, %u", SPINEL_HEADER_GET_IID(Header));
        return;
    }

    // Process the received command
    otLwfProcessSpinelCommand(pFilter, DispatchLevel, Command, Buffer, BufferLength);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS
otLwfSendTunnelPacket(
    _In_ PMS_FILTER pFilter,
    _In_ BOOLEAN DispatchLevel,
    _In_ PNET_BUFFER IpNetBuffer,
    _In_ BOOLEAN Secured
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PNET_BUFFER_LIST NetBufferList = NULL;
    PNET_BUFFER NetBuffer = NULL;
    ULONG NetBufferLength = 0;
    PUCHAR DataBuffer = NULL;
    PUCHAR IpDataBuffer = NULL;
    spinel_ssize_t PackedLength;
    IPV6_HEADER* v6Header;

    NetBufferList =
        NdisAllocateNetBufferAndNetBufferList(
            pFilter->NetBufferListPool,     // PoolHandle
            0,                              // ContextSize
            0,                              // ContextBackFill
            NULL,                           // MdlChain
            0,                              // DataOffset
            0                               // DataLength
            );
    if (NetBufferList == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        LogWarning(DRIVER_DEFAULT, "Failed to create command NetBufferList");
        goto exit;
    }
        
    // Initialize NetBuffer fields
    NetBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferList);
    NET_BUFFER_CURRENT_MDL(NetBuffer) = NULL;
    NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer) = 0;
    NET_BUFFER_DATA_LENGTH(NetBuffer) = 0;
    NET_BUFFER_DATA_OFFSET(NetBuffer) = 0;
    NET_BUFFER_FIRST_MDL(NetBuffer) = NULL;

    // Calculate length of NetBuffer
    NetBufferLength = 20 + IpNetBuffer->DataLength;
    if (NetBufferLength < 64) NetBufferLength = 64;
    
    // Allocate the NetBuffer for NetBufferList
    if (NdisRetreatNetBufferDataStart(NetBuffer, NetBufferLength, 0, NULL) != NDIS_STATUS_SUCCESS)
    {
        NetBuffer = NULL;
        status = STATUS_INSUFFICIENT_RESOURCES;
        LogError(DRIVER_DEFAULT, "Failed to allocate NB for command NetBufferList, %u bytes", NetBufferLength);
        goto exit;
    }

    // Get the pointer to the data buffer for the header data
    DataBuffer = (PUCHAR)NdisGetDataBuffer(NetBuffer, NetBufferLength, NULL, 1, 0);
    NT_ASSERT(DataBuffer);
    
    // Save the true NetBuffer length in the protocol reserved
    NetBuffer->ProtocolReserved[0] = (PVOID)NetBufferLength;
    NetBuffer->DataLength = 0;

    // Pack the header, command and key
    PackedLength = 
        spinel_datatype_pack(
            DataBuffer, 
            NetBufferLength, 
            "Cii", 
            SPINEL_HEADER_FLAG | SPINEL_HEADER_IID_0, 
            SPINEL_CMD_PROP_VALUE_IS, 
            (Secured ? SPINEL_PROP_STREAM_NET : SPINEL_PROP_STREAM_NET_INSECURE));
    if (PackedLength < 0 || PackedLength + NetBuffer->DataLength > NetBufferLength)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }

    NetBuffer->DataLength += (ULONG)PackedLength;

    // Copy the IP packet data
    IpDataBuffer = (PUCHAR)NdisGetDataBuffer(IpNetBuffer, IpNetBuffer->DataLength, DataBuffer + NetBuffer->DataLength, 1, 0);
    if (IpDataBuffer != DataBuffer + NetBuffer->DataLength)
    {
        RtlCopyMemory(IpDataBuffer, DataBuffer + NetBuffer->DataLength, NetBufferLength - NetBuffer->DataLength);
    }
    
    v6Header = (IPV6_HEADER*)(DataBuffer + NetBuffer->DataLength);

    NetBuffer->DataLength += IpNetBuffer->DataLength;
    
    // Copy over the data length
    DataBuffer[NetBuffer->DataLength+1] = (((USHORT)IpNetBuffer->DataLength) >> 8) & 0xff;
    DataBuffer[NetBuffer->DataLength]   = (((USHORT)IpNetBuffer->DataLength) >> 0) & 0xff;
                                            
    LogVerbose(DRIVER_DATA_PATH, "Filter: %p, IP6_SEND: %p : %!IPV6ADDR! => %!IPV6ADDR! (%u bytes)", 
                pFilter, NULL, &v6Header->SourceAddress, &v6Header->DestinationAddress, 
                NET_BUFFER_DATA_LENGTH(IpNetBuffer));

    // Send the NBL down
    NdisFSendNetBufferLists(
        pFilter->FilterHandle, 
        NetBufferList, 
        NDIS_DEFAULT_PORT_NUMBER, 
        DispatchLevel ? NDIS_SEND_FLAGS_DISPATCH_LEVEL : 0);

    // Clear local variable because we don't own the NBL any more
    NetBufferList = NULL;

exit:

    if (NetBufferList)
    {
        if (NetBuffer)
        {
            NetBuffer->DataLength = (ULONG)(ULONG_PTR)NetBuffer->ProtocolReserved[0];
            NdisAdvanceNetBufferDataStart(NetBuffer, NetBuffer->DataLength, TRUE, NULL);
        }
        NdisFreeNetBufferList(NetBufferList);
    }

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
spinel_tid_t
otLwfGetNextTunnelTransactionId(
    _In_ PMS_FILTER pFilter
    )
{
    spinel_tid_t TID = 0;
    while (TID == 0)
    {
        NdisAcquireSpinLock(&pFilter->tunCommandLock);

        if (((1 << pFilter->tunNextTID) & pFilter->tunTIDsInUse) == 0)
        {
            TID = pFilter->tunNextTID;
            pFilter->tunNextTID = SPINEL_GET_NEXT_TID(pFilter->tunNextTID);
        }

        NdisReleaseSpinLock(&pFilter->tunCommandLock);

        if (TID == 0)
        {
            // TODO - Wait for event
        }
    }
    return TID;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void
otLwfAddCommandHandler(
    _In_ PMS_FILTER pFilter,
    _In_ SPINEL_CMD_HANDLER_ENTRY *pEntry
    )
{
    // Get the next transaction ID. This call will block if there are
    // none currently available.
    pEntry->TransactionId = otLwfGetNextTunnelTransactionId(pFilter);

    LogFuncEntryMsg(DRIVER_DEFAULT, "tid=%u", (ULONG)pEntry->TransactionId);
    
    NdisAcquireSpinLock(&pFilter->tunCommandLock);
    
    // Add to the handlers list
    InsertTailList(&pFilter->tunCommandHandlers, &pEntry->Link);
    
    NdisReleaseSpinLock(&pFilter->tunCommandLock);

    LogFuncExit(DRIVER_DEFAULT);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
otLwfCancelCommandHandler(
    _In_ PMS_FILTER pFilter,
    _In_ BOOLEAN DispatchLevel,
    _In_ spinel_tid_t tid
    )
{
    PLIST_ENTRY Link;
    SPINEL_CMD_HANDLER_ENTRY* Handler = NULL;
    BOOLEAN Found = FALSE;

    LogFuncEntryMsg(DRIVER_DEFAULT, "tid=%u", (ULONG)tid);

    FILTER_ACQUIRE_LOCK(&pFilter->tunCommandLock, DispatchLevel);
    
    // Search for matching handlers for this transaction ID
    Link = pFilter->tunCommandHandlers.Flink;
    while (Link != &pFilter->tunCommandHandlers)
    {
        SPINEL_CMD_HANDLER_ENTRY* pEntry = CONTAINING_RECORD(Link, SPINEL_CMD_HANDLER_ENTRY, Link);
        Link = Link->Flink;

        if (tid == pEntry->TransactionId)
        {
            // Remove from the main list
            RemoveEntryList(&pEntry->Link);

            // Save handler to cancel outside lock
            Handler = pEntry;
            Found = TRUE;

            // Remove the transaction ID from the 'in use' bit field
            pFilter->tunTIDsInUse &= ~(1 << pEntry->TransactionId);

            break;
        }
    }
    
    FILTER_RELEASE_LOCK(&pFilter->tunCommandLock, DispatchLevel);

    if (Handler)
    {
        // Call the handler function
        Handler->Handler(pFilter, Handler->Context, 0, 0, NULL, 0);

        // Free the entry
        FILTER_FREE_MEM(Handler);
    }

    LogFuncExitMsg(DRIVER_DEFAULT, "Found=%u", Found);

    return Found;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfSendTunnelCommandV(
    _In_ PMS_FILTER pFilter,
    _In_ UINT Command,
    _In_ spinel_prop_key_t Key,
    _In_ spinel_tid_t tid,
    _In_ ULONG MaxDataLength,
    _In_opt_ const char *pack_format, 
    _In_opt_ va_list args
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PNET_BUFFER_LIST NetBufferList = NULL;
    PNET_BUFFER NetBuffer = NULL;
    ULONG NetBufferLength = 0;
    PUCHAR DataBuffer = NULL;
    spinel_ssize_t PackedLength;

    LogFuncEntryMsg(DRIVER_DEFAULT, "Cmd=%u Key=%u tid=%u", (ULONG)Command, (ULONG)Key, (ULONG)tid);

    NetBufferList =
        NdisAllocateNetBufferAndNetBufferList(
            pFilter->NetBufferListPool,     // PoolHandle
            0,                              // ContextSize
            0,                              // ContextBackFill
            NULL,                           // MdlChain
            0,                              // DataOffset
            0                               // DataLength
            );
    if (NetBufferList == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        LogWarning(DRIVER_DEFAULT, "Failed to create command NetBufferList");
        goto exit;
    }
        
    // Initialize NetBuffer fields
    NetBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferList);
    NET_BUFFER_CURRENT_MDL(NetBuffer) = NULL;
    NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer) = 0;
    NET_BUFFER_DATA_LENGTH(NetBuffer) = 0;
    NET_BUFFER_DATA_OFFSET(NetBuffer) = 0;
    NET_BUFFER_FIRST_MDL(NetBuffer) = NULL;

    // Calculate length of NetBuffer
    NetBufferLength = 16 + MaxDataLength;
    if (NetBufferLength < 64) NetBufferLength = 64;
    
    // Allocate the NetBuffer for NetBufferList
    if (NdisRetreatNetBufferDataStart(NetBuffer, NetBufferLength, 0, NULL) != NDIS_STATUS_SUCCESS)
    {
        NetBuffer = NULL;
        status = STATUS_INSUFFICIENT_RESOURCES;
        LogError(DRIVER_DEFAULT, "Failed to allocate NB for command NetBufferList, %u bytes", NetBufferLength);
        goto exit;
    }

    // Get the pointer to the data buffer
    DataBuffer = (PUCHAR)NdisGetDataBuffer(NetBuffer, NetBufferLength, NULL, 1, 0);
    NT_ASSERT(DataBuffer);
    
    // Save the true NetBuffer length in the protocol reserved
    NetBuffer->ProtocolReserved[0] = (PVOID)NetBufferLength;
    NetBuffer->DataLength = 0;
    
    // Save the transaction ID in the protocol reserved
    NetBuffer->ProtocolReserved[1] = (PVOID)tid;

    // Pack the header, command and key
    PackedLength = 
        spinel_datatype_pack(
            DataBuffer, 
            NetBufferLength, 
            "Cii", 
            SPINEL_HEADER_FLAG | SPINEL_HEADER_IID_0 | tid, 
            Command, 
            Key);
    if (PackedLength < 0 || PackedLength + NetBuffer->DataLength > NetBufferLength)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto exit;
    }

    NetBuffer->DataLength += (ULONG)PackedLength;

    // Pack the data (if any)
    if (pack_format)
    {
        PackedLength = 
            spinel_datatype_vpack(
                DataBuffer + NetBuffer->DataLength, 
                NetBufferLength - NetBuffer->DataLength, 
                pack_format, 
                args);
        if (PackedLength < 0 || PackedLength + NetBuffer->DataLength > NetBufferLength)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            goto exit;
        }

        NetBuffer->DataLength += (ULONG)PackedLength;
    }

    // Send the NBL down
    NdisFSendNetBufferLists(
        pFilter->FilterHandle, 
        NetBufferList, 
        NDIS_DEFAULT_PORT_NUMBER, 
        0);

    // Clear local variable because we don't own the NBL any more
    NetBufferList = NULL;

exit:

    if (NetBufferList)
    {
        if (NetBuffer)
        {
            NetBuffer->DataLength = (ULONG)(ULONG_PTR)NetBuffer->ProtocolReserved[0];
            NdisAdvanceNetBufferDataStart(NetBuffer, NetBuffer->DataLength, TRUE, NULL);
        }
        NdisFreeNetBufferList(NetBufferList);
    }

    LogFuncExitNT(DRIVER_DEFAULT, status);

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfSendTunnelCommandWithHandlerV(
    _In_ PMS_FILTER pFilter,
    _In_opt_ SPINEL_CMD_HANDLER *Handler,
    _In_opt_ PVOID HandlerContext,
    _In_ UINT Command,
    _In_ spinel_prop_key_t Key,
    _In_ ULONG MaxDataLength,
    _In_opt_ const char *pack_format, 
    _In_opt_ va_list args
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    SPINEL_CMD_HANDLER_ENTRY *pEntry = NULL;

    // Create the handler entry and add it to the list
    if (Handler)
    {
        pEntry = FILTER_ALLOC_MEM(pFilter->FilterHandle, sizeof(SPINEL_CMD_HANDLER_ENTRY));
        if (pEntry == NULL)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            LogWarning(DRIVER_DEFAULT, "Failed to allocate handler entry");
            goto exit;
        }

        pEntry->Handler = Handler;
        pEntry->Context = HandlerContext;

        otLwfAddCommandHandler(pFilter, pEntry);
    }
    
    status = otLwfSendTunnelCommandV(pFilter, Command, Key, pEntry ? pEntry->TransactionId : 0, MaxDataLength, pack_format, args);

    // Remove the handler entry from the list
    if (!NT_SUCCESS(status) && pEntry)
    {
        NdisAcquireSpinLock(&pFilter->tunCommandLock);
    
        // Remove from the main list
        RemoveEntryList(&pEntry->Link);

        // Remove the transaction ID from the 'in use' bit field
        pFilter->tunTIDsInUse &= ~(1 << pEntry->TransactionId);

        NdisReleaseSpinLock(&pFilter->tunCommandLock);

        // TODO - Set event

        FILTER_FREE_MEM(pEntry);
    }

exit:

    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfSendTunnelCommandWithHandler(
    _In_ PMS_FILTER pFilter,
    _In_opt_ SPINEL_CMD_HANDLER *Handler,
    _In_opt_ PVOID HandlerContext,
    _In_ UINT Command,
    _In_ spinel_prop_key_t Key,
    _In_ ULONG MaxDataLength,
    _In_opt_ const char *pack_format, 
    ...
    )
{
    va_list args;
    va_start(args, pack_format);
    NTSTATUS status = 
        otLwfSendTunnelCommandWithHandlerV(pFilter, Handler, HandlerContext, Command, Key, MaxDataLength, pack_format, args);
    va_end(args);
    return status;
}

SPINEL_CMD_HANDLER otLwfIrpCommandHandler;

typedef struct _SPINEL_IRP_CMD_CONTEXT
{
    PIRP                    Irp;
    SPINEL_IRP_CMD_HANDLER *Handler;
} SPINEL_IRP_CMD_CONTEXT;

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
otLwfIrpCommandHandler(
    _In_ PMS_FILTER pFilter,
    _In_ PVOID Context,
    _In_ UINT Command,
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength
    )
{
    SPINEL_IRP_CMD_CONTEXT* CmdContext = (SPINEL_IRP_CMD_CONTEXT*)Context;
    PIO_STACK_LOCATION  IrpSp = IoGetCurrentIrpStackLocation(CmdContext->Irp);
    
    ULONG IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID OutBuffer = CmdContext->Irp->AssociatedIrp.SystemBuffer;
    ULONG OutBufferLength = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG OrigOutBufferLength = OutBufferLength;

    NTSTATUS status;

    UNREFERENCED_PARAMETER(pFilter);
    
    if (Data == NULL)
    {
        status = STATUS_CANCELLED;
        OutBufferLength = 0;
    }
    else if (Command == SPINEL_CMD_PROP_VALUE_IS && Key == SPINEL_PROP_LAST_STATUS)
    {
        spinel_status_t spinel_status = SPINEL_STATUS_OK;
        spinel_ssize_t packed_len = spinel_datatype_unpack(Data, DataLength, "i", &spinel_status);
        if (packed_len < 0 || (ULONG)packed_len > DataLength)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            status = ThreadErrorToNtstatus(SpinelStatusToThreadError(spinel_status));
        }
    }
    else if (CmdContext->Handler)
    {
        status = CmdContext->Handler(Key, Data, DataLength, OutBuffer, &OutBufferLength);
    }
    else // No handler, so no output
    {
        status = STATUS_SUCCESS;
        OutBufferLength = 0;
    }

    // Clear any leftover output buffer
    if (OutBufferLength < OrigOutBufferLength)
    {
        RtlZeroMemory((PUCHAR)OutBuffer + OutBufferLength, OrigOutBufferLength - OutBufferLength);
    }

    LogVerbose(DRIVER_IOCTL, "Completing Irp=%p, with %!STATUS! for %s (Out:%u)", 
                CmdContext->Irp, status, IoCtlString(IoControlCode), OutBufferLength);

    // Complete the IRP
    CmdContext->Irp->IoStatus.Information = OutBufferLength;
    CmdContext->Irp->IoStatus.Status = status;
    IoCompleteRequest(CmdContext->Irp, IO_NO_INCREMENT);

    FILTER_FREE_MEM(Context);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfSendTunnelCommandForIrp(
    _In_ PMS_FILTER pFilter,
    _In_ PIRP Irp,
    _In_opt_ SPINEL_IRP_CMD_HANDLER *Handler,
    _In_ UINT Command,
    _In_ spinel_prop_key_t Key,
    _In_ ULONG MaxDataLength,
    _In_opt_ const char *pack_format, 
    ...
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    SPINEL_IRP_CMD_CONTEXT *pContext = NULL;

    // Create the context structure
    pContext = FILTER_ALLOC_MEM(pFilter->FilterHandle, sizeof(SPINEL_IRP_CMD_CONTEXT));
    if (pContext == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        LogWarning(DRIVER_DEFAULT, "Failed to allocate irp cmd context");
        goto exit;
    }

    pContext->Irp = Irp;
    pContext->Handler = Handler;
    
    va_list args;
    va_start(args, pack_format);
    status = 
        otLwfSendTunnelCommandWithHandlerV(
            pFilter, 
            otLwfIrpCommandHandler, 
            pContext, 
            Command, 
            Key, 
            MaxDataLength, 
            pack_format, 
            args);
    va_end(args);

    // Remove the handler entry from the list
    if (!NT_SUCCESS(status))
    {
        FILTER_FREE_MEM(pContext);
    }

exit:

    return status;
}

typedef struct _SPINEL_GET_PROP_CONTEXT
{
    KEVENT              CompletionEvent;
    spinel_prop_key_t   Key;
    const char*         Format;
    va_list             Args;
    NTSTATUS            Status;
} SPINEL_GET_PROP_CONTEXT;

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
otLwfGetPropHandler(
    _In_ PMS_FILTER pFilter,
    _In_ PVOID Context,
    _In_ UINT Command,
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength
    )
{
    SPINEL_GET_PROP_CONTEXT* CmdContext = (SPINEL_GET_PROP_CONTEXT*)Context;

    LogFuncEntryMsg(DRIVER_DEFAULT, "Key=%u", (ULONG)Key);

    UNREFERENCED_PARAMETER(pFilter);
    
    if (Data == NULL)
    {
        CmdContext->Status = STATUS_CANCELLED;
    }
    else if (Command != SPINEL_CMD_PROP_VALUE_IS)
    {
        CmdContext->Status = STATUS_INVALID_PARAMETER;
    }
    else if (Key == SPINEL_PROP_LAST_STATUS)
    {
        spinel_status_t spinel_status = SPINEL_STATUS_OK;
        spinel_ssize_t packed_len = spinel_datatype_unpack(Data, DataLength, "i", &spinel_status);
        if (packed_len < 0 || (ULONG)packed_len > DataLength)
        {
            CmdContext->Status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            CmdContext->Status = ThreadErrorToNtstatus(SpinelStatusToThreadError(spinel_status));
        }
    }
    else if (Key == CmdContext->Key)
    {
        spinel_ssize_t packed_len = spinel_datatype_vunpack(Data, DataLength, CmdContext->Format, CmdContext->Args);
        if (packed_len < 0 || (ULONG)packed_len > DataLength)
        {
            CmdContext->Status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            CmdContext->Status = STATUS_SUCCESS;
        }
    }
    else
    {
        CmdContext->Status = STATUS_INVALID_PARAMETER;
    }

    // Set the completion event
    KeSetEvent(&CmdContext->CompletionEvent, 0, FALSE);

    LogFuncExit(DRIVER_DEFAULT);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfGetTunProp(
    _In_ PMS_FILTER pFilter,
    _In_ spinel_prop_key_t Key,
    _In_ const char *pack_format, 
    ...
    )
{
    NTSTATUS status;
    LARGE_INTEGER WaitTimeout;

    // Create the context structure
    SPINEL_GET_PROP_CONTEXT Context;
    KeInitializeEvent(&Context.CompletionEvent, SynchronizationEvent, FALSE);
    Context.Key = Key;
    Context.Format = pack_format;
    Context.Status = STATUS_SUCCESS;
    va_start(Context.Args, pack_format);

    LogFuncEntryMsg(DRIVER_DEFAULT, "Key=%u", (ULONG)Key);

    // Send the request transaction
    status = 
        otLwfSendTunnelCommandWithHandlerV(
            pFilter, 
            otLwfGetPropHandler, 
            &Context, 
            SPINEL_CMD_PROP_VALUE_GET, 
            Key, 
            0, 
            NULL,
            NULL);
    if (NT_SUCCESS(status))
    {
        // Set a 1 second wait timeout
        WaitTimeout.QuadPart = -1000 * 10000;

        // Wait for the response
        if (!NT_SUCCESS(
            KeWaitForSingleObject(
                &Context.CompletionEvent,
                Executive,
                KernelMode,
                FALSE,
                &WaitTimeout)
            ))
        {
            /* TODO - Get TID to use for cancel
            if (!otLwfCancelCommandHandler(pFilter, FALSE, tid))
            {
                KeWaitForSingleObject(
                    &Context.CompletionEvent,
                    Executive,
                    KernelMode,
                    FALSE,
                    NULL);
            }*/
            Context.Status = STATUS_CANCELLED;
        }
    }
    else
    {
        Context.Status = status;
    }
    
    va_end(Context.Args);

    LogFuncExitNT(DRIVER_DEFAULT, Context.Status);

    return Context.Status;
}

typedef struct _SPINEL_SET_PROP_CONTEXT
{
    KEVENT              CompletionEvent;
    spinel_prop_key_t   Key;
    NTSTATUS            Status;
} SPINEL_SET_PROP_CONTEXT;

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
otLwfSetPropHandler(
    _In_ PMS_FILTER pFilter,
    _In_ PVOID Context,
    _In_ UINT Command,
    _In_ spinel_prop_key_t Key,
    _In_reads_bytes_(DataLength) const uint8_t* Data,
    _In_ spinel_size_t DataLength
    )
{
    SPINEL_SET_PROP_CONTEXT* CmdContext = (SPINEL_SET_PROP_CONTEXT*)Context;

    LogFuncEntryMsg(DRIVER_DEFAULT, "Key=%u", (ULONG)Key);

    UNREFERENCED_PARAMETER(pFilter);
    
    if (Data == NULL)
    {
        CmdContext->Status = STATUS_CANCELLED;
    }
    else if (Command != SPINEL_CMD_PROP_VALUE_IS)
    {
        CmdContext->Status = STATUS_INVALID_PARAMETER;
    }
    else if (Key == SPINEL_PROP_LAST_STATUS)
    {
        spinel_status_t spinel_status = SPINEL_STATUS_OK;
        spinel_ssize_t packed_len = spinel_datatype_unpack(Data, DataLength, "i", &spinel_status);
        if (packed_len < 0 || (ULONG)packed_len > DataLength)
        {
            CmdContext->Status = STATUS_INSUFFICIENT_RESOURCES;
        }
        else
        {
            CmdContext->Status = ThreadErrorToNtstatus(SpinelStatusToThreadError(spinel_status));
        }
    }
    else if (Key == CmdContext->Key)
    {
        CmdContext->Status = STATUS_SUCCESS;
    }
    else
    {
        CmdContext->Status = STATUS_INVALID_PARAMETER;
    }

    // Set the completion event
    KeSetEvent(&CmdContext->CompletionEvent, 0, FALSE);

    LogFuncExit(DRIVER_DEFAULT);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
otLwfSetTunProp(
    _In_ PMS_FILTER pFilter,
    _In_ spinel_prop_key_t Key,
    _In_ const char *pack_format, 
    ...
    )
{
    NTSTATUS status;
    LARGE_INTEGER WaitTimeout;

    // Create the context structure
    SPINEL_SET_PROP_CONTEXT Context;
    KeInitializeEvent(&Context.CompletionEvent, SynchronizationEvent, FALSE);
    Context.Key = Key;
    Context.Status = STATUS_SUCCESS;

    LogFuncEntryMsg(DRIVER_DEFAULT, "Key=%u", (ULONG)Key);

    va_list args;
    va_start(args, pack_format);

    // Send the request transaction
    status = 
        otLwfSendTunnelCommandWithHandlerV(
            pFilter, 
            otLwfGetPropHandler, 
            &Context, 
            SPINEL_CMD_PROP_VALUE_SET, 
            Key, 
            8, 
            pack_format,
            args);
    if (NT_SUCCESS(status))
    {
        // Set a 1 second wait timeout
        WaitTimeout.QuadPart = -1000 * 10000;

        // Wait for the response
        if (!NT_SUCCESS(
            KeWaitForSingleObject(
                &Context.CompletionEvent,
                Executive,
                KernelMode,
                FALSE,
                &WaitTimeout)
            ))
        {
            /* TODO - Get TID to use for cancel
            if (!otLwfCancelCommandHandler(pFilter, FALSE, tid))
            {
                KeWaitForSingleObject(
                    &Context.CompletionEvent,
                    Executive,
                    KernelMode,
                    FALSE,
                    NULL);
            }*/
            Context.Status = STATUS_CANCELLED;
        }
    }
    else
    {
        Context.Status = status;
    }
    
    va_end(args);

    LogFuncExitNT(DRIVER_DEFAULT, Context.Status);

    return Context.Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
void 
otLwfProcessSpinelIPv6Packet(
    _In_ PMS_FILTER pFilter,
    _In_ BOOLEAN DispatchLevel,
    _In_ BOOLEAN Secure,
    _In_reads_bytes_(BufferLength) const uint8_t* Buffer,
    _In_ UINT BufferLength
    )
{
    NTSTATUS status = STATUS_SUCCESS;
    PNET_BUFFER_LIST NetBufferList = NULL;
    PNET_BUFFER NetBuffer = NULL;
    PUCHAR DataBuffer = NULL;
    IPV6_HEADER* v6Header;

    UNREFERENCED_PARAMETER(Secure); // TODO - What should we do with unsecured packets?

    NetBufferList =
        NdisAllocateNetBufferAndNetBufferList(
            pFilter->NetBufferListPool,     // PoolHandle
            0,                              // ContextSize
            0,                              // ContextBackFill
            NULL,                           // MdlChain
            0,                              // DataOffset
            0                               // DataLength
            );
    if (NetBufferList == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        LogWarning(DRIVER_DEFAULT, "Failed to create command NetBufferList");
        goto exit;
    }

    // Set the flag to indicate its a IPv6 packet
    NdisSetNblFlag(NetBufferList, NDIS_NBL_FLAGS_IS_IPV6);
    NET_BUFFER_LIST_INFO(NetBufferList, NetBufferListFrameType) =
        UlongToPtr(RtlUshortByteSwap(ETHERNET_TYPE_IPV6));
        
    // Initialize NetBuffer fields
    NetBuffer = NET_BUFFER_LIST_FIRST_NB(NetBufferList);
    NET_BUFFER_CURRENT_MDL(NetBuffer) = NULL;
    NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer) = 0;
    NET_BUFFER_DATA_LENGTH(NetBuffer) = 0;
    NET_BUFFER_DATA_OFFSET(NetBuffer) = 0;
    NET_BUFFER_FIRST_MDL(NetBuffer) = NULL;
    
    // Allocate the NetBuffer for NetBufferList
    if (NdisRetreatNetBufferDataStart(NetBuffer, BufferLength, 0, NULL) != NDIS_STATUS_SUCCESS)
    {
        NetBuffer = NULL;
        status = STATUS_INSUFFICIENT_RESOURCES;
        LogError(DRIVER_DEFAULT, "Failed to allocate NB for command NetBufferList, %u bytes", BufferLength);
        goto exit;
    }

    // Get the pointer to the data buffer for the header data
    DataBuffer = (PUCHAR)NdisGetDataBuffer(NetBuffer, BufferLength, NULL, 1, 0);
    NT_ASSERT(DataBuffer);
    
    // Copy the data over
    RtlCopyMemory(DataBuffer, Buffer, BufferLength);

    v6Header = (IPV6_HEADER*)DataBuffer;
    
    // Filter messages to addresses we expose
    if (!IN6_IS_ADDR_MULTICAST(&v6Header->DestinationAddress) &&
        otLwfFindCachedAddrIndex(pFilter, &v6Header->DestinationAddress) == -1)
    {
        LogVerbose(DRIVER_DATA_PATH, "Filter: %p dropping internal address message.", pFilter);
        goto exit;
    }
    
    // Filter internal Thread messages
    /*if (v6Header->NextHeader == IPPROTO_UDP &&
        BufferLength >= sizeof(IPV6_HEADER) + sizeof(UDPHeader) &&
        memcmp(&pFilter->otLinkLocalAddr, &v6Header->DestinationAddress, sizeof(IN6_ADDR)) == 0)
    {
        // Check for MLE message
        UDPHeader* UdpHeader = (UDPHeader*)(v6Header + 1);
        if (UdpHeader->DestinationPort == UdpHeader->SourcePort &&
            UdpHeader->DestinationPort == RtlUshortByteSwap(19788)) // MLE Port
        {
            LogVerbose(DRIVER_DATA_PATH, "Filter: %p dropping MLE message.", pFilter);
            goto exit;
        }
    }*/
    
    LogVerbose(DRIVER_DATA_PATH, "Filter: %p, IP6_RECV: %p : %!IPV6ADDR! => %!IPV6ADDR! (%u bytes)", 
               pFilter, NetBufferList, &v6Header->SourceAddress, &v6Header->DestinationAddress,
               BufferLength);

#ifdef LOG_BUFFERS
    otLogBuffer(DataBuffer, BufferLength);
#endif

    // Send the NBL down
    NdisFIndicateReceiveNetBufferLists(
        pFilter->FilterHandle, 
        NetBufferList, 
        NDIS_DEFAULT_PORT_NUMBER,
        1,
        DispatchLevel ? NDIS_RECEIVE_FLAGS_DISPATCH_LEVEL : 0);

    // Clear local variable because we don't own the NBL any more
    NetBufferList = NULL;

exit:

    if (NetBufferList)
    {
        if (NetBuffer)
        {
            NdisAdvanceNetBufferDataStart(NetBuffer, NetBuffer->DataLength, TRUE, NULL);
        }
        NdisFreeNetBufferList(NetBufferList);
    }
}
