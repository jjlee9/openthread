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

_IRQL_requires_max_(PASSIVE_LEVEL)
NDIS_STATUS 
otLwfInitializeTunnelMode(
    _In_ PMS_FILTER pFilter
    )
{
    NDIS_STATUS Status = NDIS_STATUS_SUCCESS;

    LogFuncEntry(DRIVER_DEFAULT);

    UNREFERENCED_PARAMETER(pFilter);

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
    LogFuncExit(DRIVER_DEFAULT);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void 
otLwfProcessSpinelIPv6Packet(
    _In_ PMS_FILTER pFilter,
    _In_ BOOLEAN Secure,
    _In_reads_bytes_(BufferLength) const uint8_t* Buffer,
    _In_ spinel_size_t BufferLength
    )
{
    UNREFERENCED_PARAMETER(pFilter);
    UNREFERENCED_PARAMETER(Secure);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(BufferLength);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void 
otLwfProcessSpinelValueIs(
    _In_ PMS_FILTER pFilter,
    _In_ spinel_prop_key_t key,
    _In_reads_bytes_(value_data_len) const uint8_t* value_data_ptr,
    _In_ spinel_size_t value_data_len
    )
{
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
        else if (status == SPINEL_STATUS_INVALID_COMMAND) 
        {
			LogVerbose(DRIVER_DEFAULT, "NCP command not recognized");
		}
	} 
    else if (key == SPINEL_PROP_IPV6_ADDRESS_TABLE) 
    {
        // TODO - Update cached addresses
	} 
    else if (key == SPINEL_PROP_STREAM_DEBUG) 
    {
        // TODO - Log
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
	} 
    else if (key == SPINEL_PROP_THREAD_ON_MESH_NETS) 
    {
		// TODO - Slaac
	} 
    else if (key == SPINEL_PROP_STREAM_RAW) 
    {
        // May be used in the future
	} 
    else if ((key == SPINEL_PROP_STREAM_NET) || (key == SPINEL_PROP_STREAM_NET_INSECURE)) 
    {
		const uint8_t* frame_ptr = NULL;
		unsigned int frame_len = 0;
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
                (SPINEL_PROP_STREAM_NET_INSECURE == key) ? FALSE : TRUE,
                frame_ptr,
                frame_len);
		}
	}

    LogFuncExit(DRIVER_DEFAULT);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void 
otLwfProcessSpinelCommand(
    _In_ PMS_FILTER pFilter,
    _In_ UINT command,
    _In_reads_bytes_(cmd_data_len) const uint8_t* cmd_data_ptr,
    _In_ spinel_size_t cmd_data_len
    )
{
	spinel_prop_key_t key;
	uint8_t* value_data_ptr = NULL;
	spinel_size_t value_data_len = 0;

    // Make sure it's an expected command
    if (command < SPINEL_CMD_PROP_VALUE_IS || command >SPINEL_CMD_PROP_VALUE_REMOVED)
    {
        LogVerbose(DRIVER_DEFAULT, "Recieved unhandled command, %u", command);
        return;
    }

    // Decode the key and data
    if (spinel_datatype_unpack(cmd_data_ptr, cmd_data_len, "CiiD", NULL, NULL, &key, &value_data_ptr, &value_data_len) == -1)
    {
        LogVerbose(DRIVER_DEFAULT, "Failed to unpack command key & data");
        return;
    }

    // If this is a 'Value Is' command, process it for notification of state changes
    if (command == SPINEL_CMD_PROP_VALUE_IS)
    {
		otLwfProcessSpinelValueIs(pFilter, key, value_data_ptr, value_data_len);
    }

    // TODO - Indicate received value for callbacks
}

_IRQL_requires_max_(PASSIVE_LEVEL)
void 
otLwfReceiveTunnelPacket(
    _In_ PMS_FILTER pFilter,
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
	otLwfProcessSpinelCommand(pFilter, Command, Buffer, BufferLength);
}
