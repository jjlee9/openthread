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
    uint8_t buf[64];
    spinel_ssize_t packed_len;

    LogFuncEntry(DRIVER_DEFAULT);

    UNREFERENCED_PARAMETER(pFilter);

    packed_len = spinel_datatype_pack(buf, sizeof(buf), SPINEL_DATATYPE_UINT_PACKED_S, SPINEL_CAP_NET_THREAD_1_0);

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
