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

#include "stdafx.h"
#include "border-router-socket.hpp"

BRSocket::BRSocket(ADDRESS_FAMILY addressFamily, BrSocketReadCallback readCallback, void* clientContext) :
    mSocket(INVALID_SOCKET),
    mAddressFamily(addressFamily),
    mOverlapped({ 0 }),
    mClientReceiveCallback(readCallback),
    mClientContext(clientContext),
    mIsReading(false)
{
}

BRSocket::~BRSocket()
{
    Uninitialize();
}

HRESULT BRSocket::Initialize()
{
    mSocket = WSASocketW(mAddressFamily, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
    if (mSocket == INVALID_SOCKET)
    {
        return HRESULT_FROM_WIN32(WSAGetLastError());
    }

    // from MSDN documentation on WSARecvFrom:
    // "If lpCompletionRoutine is not NULL, the hEvent parameter is ignored and can be used by
    // the application to pass context information to the completion routine"
    // We will use this to provide a this ptr to call member functions with
    mOverlapped.hEvent = this;

    return S_OK;
}

void BRSocket::Uninitialize()
{
    if (mSocket != INVALID_SOCKET)
    {
        closesocket(mSocket);
    }
    mIsReading = false;
}

HRESULT BRSocket::Bind(unsigned short port, PIN6_ADDR sin6Addr)
{
    if (mAddressFamily == AF_INET)
    {
        sockaddr_in recvAddr = {};
        recvAddr.sin_family = AF_INET;
        recvAddr.sin_addr.s_addr = htonl(INADDR_ANY);
        recvAddr.sin_port = htons(port);

        if (SOCKET_ERROR == bind(mSocket, (sockaddr*)&recvAddr, sizeof(recvAddr)))
        {
            return HRESULT_FROM_WIN32(WSAGetLastError());
        }
    }
    else
    {
        sockaddr_in6 recvAddr = {};
        recvAddr.sin6_family = AF_INET6;
        recvAddr.sin6_addr = sin6Addr != nullptr ? *sin6Addr : in6addr_any;
        recvAddr.sin6_port = htons(port);

        if (SOCKET_ERROR == bind(mSocket, (sockaddr*)&recvAddr, sizeof(recvAddr)))
        {
            return HRESULT_FROM_WIN32(WSAGetLastError());
        }
    }

    return S_OK;
}

// static
void CALLBACK BRSocket::AsyncSocketWaitComplete(DWORD dwError,
                                                DWORD cbTransferred,
                                                LPWSAOVERLAPPED lpOverlapped,
                                                DWORD dwFlags)
{
    auto pThis = static_cast<BRSocket*>(lpOverlapped->hEvent);

    if (dwError == ERROR_SUCCESS)
    {
        wprintf(L"%p: Looks like we got a message! dwFlags is 0x%x, cbTransferred is %d\n", pThis, dwFlags, cbTransferred);

        // Let the client handle their callback before reading from the socket again so callbacks are
        // serialized
        pThis->mClientReceiveCallback(pThis->mClientContext, (uint8_t*)pThis->mRecvBuffer, cbTransferred);
    }
    else
    {
        wprintf(L"%p: Error in AsyncSocketWaitComplete indicated, %d\n", pThis, dwError);
    }

    pThis->Read();
}

HRESULT BRSocket::Read()
{
    WSABUF wsaRecvBuffer = { sizeof(mRecvBuffer), mRecvBuffer };
    DWORD cbReceived = 0;
    DWORD dwFlags = MSG_PARTIAL;

    int cbSourceAddr = sizeof(mPeerAddr);

    mIsReading = true;

    if (SOCKET_ERROR == WSARecvFrom(mSocket, &wsaRecvBuffer, 1, &cbReceived, &dwFlags, reinterpret_cast<sockaddr*>(&mPeerAddr), &cbSourceAddr, &mOverlapped, AsyncSocketWaitComplete))
    {
        DWORD dwError = WSAGetLastError();
        if (WSA_IO_PENDING != dwError)
        {
            wprintf(L"%p: We failed to RecvFrom. The error is %d\n", this, dwError);
            return HRESULT_FROM_WIN32(dwError);
        }
    }

    return S_OK;
}

bool BRSocket::IsReading()
{
    return mIsReading;
}

HRESULT BRSocket::Reply(const uint8_t* aBuf, uint16_t aLength, unsigned short port)
{
    if (port != 0 && mAddressFamily == AF_INET)
    {
        reinterpret_cast<sockaddr_in*>(&mPeerAddr)->sin_port = htons(port);
    }
    else if (port != 0)
    {
        reinterpret_cast<sockaddr_in6*>(&mPeerAddr)->sin6_port = htons(port);
    }
    return SendTo(aBuf, aLength, reinterpret_cast<sockaddr*>(&mPeerAddr), sizeof(mPeerAddr));
}

HRESULT BRSocket::SendTo(const uint8_t* aBuf, uint16_t aLength, sockaddr_in6* peerToSendTo)
{
    return SendTo(aBuf, aLength, reinterpret_cast<sockaddr*>(peerToSendTo), sizeof(*peerToSendTo));
}

HRESULT BRSocket::SendTo(const uint8_t* aBuf, uint16_t aLength, sockaddr_in* peerToSendTo)
{
    return SendTo(aBuf, aLength, reinterpret_cast<sockaddr*>(peerToSendTo), sizeof(*peerToSendTo));
}

HRESULT BRSocket::SendTo(const uint8_t* aBuf, uint16_t aLength, sockaddr* peerToSendTo, size_t cbSizeOfPeerToSendTo)
{
    DWORD result = sendto(mSocket, (char*)aBuf, (int)aLength, 0, peerToSendTo, (int)cbSizeOfPeerToSendTo);
    if (result == SOCKET_ERROR)
    {
        DWORD wsaError = WSAGetLastError();
        wprintf(L"%p: wsaError in SendTo occurred. %d\n", this, wsaError);
        return HRESULT_FROM_WIN32(wsaError);
    }
    else
    {
        wprintf(L"%p: wrote %d bytes out of %d in SendTo\n", this, result, aLength);
        return S_OK;
    }
}

void BRSocket::GetLastPeer(sockaddr_storage* lastPeer)
{
    *lastPeer = mPeerAddr;
}