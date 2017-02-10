/*
 *  Copyright (c) 2016, Nest Labs, Inc.
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
 *   This file implements the CoAP server message dispatch.
 */

#include "stdafx.h"
#include "br_coap_server.hpp"
#include <common/code_utils.hpp>

namespace OffMesh {
namespace Coap {

Server::Server(void):
    mResources(NULL)
{
}

ThreadError Server::AddResource(Resource &aResource)
{
    ThreadError error = kThreadError_None;

    for (Resource *cur = mResources; cur; cur = cur->mNext)
    {
        VerifyOrExit(cur != &aResource, error = kThreadError_Busy);
    }

    aResource.mNext = mResources;
    mResources = &aResource;

exit:
    return error;
}

void Server::Receive(uint8_t *aMessage, uint16_t aLength)
{
    OffMesh::Coap::Header header;
    char uriPath[kMaxReceivedUriPath];
    char *curUriPath = uriPath;
    const OffMesh::Coap::Header::Option *coapOption;

    SuccessOrExit(header.FromBytes(aMessage, aLength));
    uint8_t headerLength = header.GetLength();

    coapOption = header.GetCurrentOption();

    auto bytes = header.GetBytes();

    while (coapOption != NULL)
    {
        switch (coapOption->mNumber)
        {
        case OffMesh::Coap::Header::Option::kOptionUriPath:
            VerifyOrExit(coapOption->mLength < sizeof(uriPath) - static_cast<size_t>(curUriPath - uriPath), ;);
            memcpy(curUriPath, coapOption->mValue, coapOption->mLength);
            curUriPath[coapOption->mLength] = '/';
            curUriPath += coapOption->mLength + 1;
            break;

        case OffMesh::Coap::Header::Option::kOptionContentFormat:
            break;

        default:
            //wprintf(L"We found a weird option, it was %u. Ignore it for now, but this is an error from the client!\n", (unsigned int)coapOption->mNumber);
            break;
            //ExitNow();
        }

        coapOption = header.GetNextOption();
    }

    curUriPath[-1] = '\0';

    for (Resource *resource = mResources; resource; resource = resource->mNext)
    {
        resource->HandleRequest(header, aMessage + headerLength, aLength - headerLength, uriPath);
    }

exit:
    {}
}

}  // namespace Coap
}  // namespace OffMesh
