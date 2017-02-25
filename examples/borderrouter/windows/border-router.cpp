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
#include <mbedtls/memory_buffer_alloc.h>
#include <common/message.hpp>
#include <thread/thread_uris.hpp>
#include <thread/thread_tlvs.hpp>
#include <crypto/mbedtls.hpp>
#include <memory>
#include "border-router.hpp"

#ifdef OPENTHREAD_CONFIG_FILE
#include OPENTHREAD_CONFIG_FILE
#else
#include <openthread-config.h>
#endif

#include <openthread-core-config.h>
#include <openthread.h>

extern "C" void *otPlatCAlloc(size_t aNum, size_t aSize)
{
    return calloc(aNum, aSize);
}

extern "C" void otPlatFree(void *aPtr)
{
    free(aPtr);
}

void printBuffer(char* buffer, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02x", (unsigned char)*buffer++);
        if (i % 4 == 3)
        {
            printf(" ");
        }
    }
    printf("\n");
}

HRESULT GeneratePSKc(const char* passPhrase, const char* networkName, const uint8_t* extPanId, uint8_t* derivedKeyOut)
{
    HRESULT hr = S_OK;

    const char* saltPrefix = "Thread";
    BCRYPT_ALG_HANDLE hKeyPbkdf2AlgoProv = nullptr;
    BCRYPT_ALG_HANDLE hKeyAesCmacAlgoProv = nullptr;
    BCRYPT_HASH_HANDLE  hHash = nullptr;
    BCRYPT_KEY_HANDLE hKeySymmetricKey = nullptr;

    const size_t prefixLen = strlen(saltPrefix);
    const size_t networkLen = strlen(networkName);
    size_t saltLen = prefixLen + OT_EXT_PAN_ID_SIZE + networkLen;

    // prepare the salt
    auto salt = std::unique_ptr<uint8_t[]>(new (std::nothrow) uint8_t[saltLen]);
    if (salt == nullptr)
    {
        hr = E_OUTOFMEMORY;
        goto exit;
    }

    memset(salt.get(), 0, saltLen);
    memcpy_s(salt.get(), saltLen, saltPrefix, prefixLen);

    for (size_t i = 0; i < OT_EXT_PAN_ID_SIZE; i++) {
        salt[prefixLen + i] = extPanId[i];
    }

    memcpy_s(salt.get() + prefixLen + OT_EXT_PAN_ID_SIZE, networkLen, networkName, networkLen);

    // Get a handle to the algorithm provider
    NTSTATUS ntStatus = BCryptOpenAlgorithmProvider(
        &hKeyPbkdf2AlgoProv,
        BCRYPT_PBKDF2_ALGORITHM,
        nullptr,
        0);
    if (!BCRYPT_SUCCESS(ntStatus))
    {
        hr = HRESULT_FROM_NT(ntStatus);
        printf("BCryptOpenAlgorithmProvider for BCRYPT_PBKDF2_ALGORITHM failed, 0x%x!\n", hr);
        goto exit;
    }
        
    ntStatus = BCryptOpenAlgorithmProvider(
        &hKeyAesCmacAlgoProv,
        BCRYPT_AES_CMAC_ALGORITHM,
        nullptr,
        0);
    if (!BCRYPT_SUCCESS(ntStatus))
    {
        hr = HRESULT_FROM_NT(ntStatus);
        printf("BCryptOpenAlgorithmProvider for BCRYPT_AES_CMAC_ALGORITHM failed, 0x%x!\n", hr);
        goto exit;
    }
        
    uint8_t zeroKey[16] = {};
    ntStatus = BCryptCreateHash(hKeyAesCmacAlgoProv, &hHash, nullptr, 0, zeroKey, sizeof(zeroKey), 0);
    if (!BCRYPT_SUCCESS(ntStatus))
    {
        hr = HRESULT_FROM_NT(ntStatus);
        printf("BCryptCreateHash failed, 0x%x!\n", hr);
        goto exit;
    }

    ntStatus = BCryptHashData(hHash, (PUCHAR)passPhrase, (ULONG)strlen(passPhrase), 0);
    if (!BCRYPT_SUCCESS(ntStatus))
    {
        hr = HRESULT_FROM_NT(ntStatus);
        printf("BCryptHashData failed, 0x%x!\n", hr);
        goto exit;
    }

    BYTE res1[16];
    ntStatus = BCryptFinishHash(hHash, res1, sizeof(res1), 0);
    if (!BCRYPT_SUCCESS(ntStatus))
    {
        hr = HRESULT_FROM_NT(ntStatus);
        printf("BCryptFinishHash failed, 0x%x!\n", hr);
        goto exit;
    }

    BCryptBufferDesc    ParamList;
    BCryptBuffer        pParamBuffer[3] = {};

    pParamBuffer[0].BufferType = KDF_HASH_ALGORITHM;
    pParamBuffer[0].cbBuffer = (ULONG)wcslen(BCRYPT_AES_CMAC_ALGORITHM) * sizeof(WCHAR);
    pParamBuffer[0].pvBuffer = (void*)BCRYPT_AES_CMAC_ALGORITHM;

    ULONGLONG ulIteration = 16384;
    pParamBuffer[1].BufferType = KDF_ITERATION_COUNT;
    pParamBuffer[1].cbBuffer = sizeof(ulIteration);
    pParamBuffer[1].pvBuffer = &ulIteration;

    pParamBuffer[2].BufferType = KDF_SALT;
    pParamBuffer[2].cbBuffer = (ULONG)saltLen;
    pParamBuffer[2].pvBuffer = salt.get();

    ParamList.cBuffers = 3;
    ParamList.pBuffers = pParamBuffer;
    ParamList.ulVersion = BCRYPTBUFFER_VERSION;

    ntStatus = BCryptGenerateSymmetricKey(
        hKeyPbkdf2AlgoProv,
        &hKeySymmetricKey,
        nullptr,
        0,
        res1,
        sizeof(res1),
        0);

    if (!BCRYPT_SUCCESS(ntStatus))
    {
        hr = HRESULT_FROM_NT(ntStatus);
        printf("BCryptGenerateSymmetricKey failed, 0x%x\n", hr);
        goto exit;
    }

    DWORD cbResult = 0;
    ntStatus = BCryptKeyDerivation(hKeySymmetricKey,
        &ParamList,
        derivedKeyOut,
        16,
        &cbResult,
        0
    );

    if (!BCRYPT_SUCCESS(ntStatus))
    {
        hr = HRESULT_FROM_NT(ntStatus);
        printf("BCryptKeyDerivation failed, 0x%x\n", hr);
        goto exit;
    }

    printf("PSKc Stretched Key:\n");
    printBuffer((char*)derivedKeyOut, 16);

exit:

    if (hKeyPbkdf2AlgoProv)
    {
        BCryptCloseAlgorithmProvider(hKeyPbkdf2AlgoProv, 0);
    }

    if (hKeyAesCmacAlgoProv)
    {
        BCryptCloseAlgorithmProvider(hKeyAesCmacAlgoProv, 0);
    }

    if (hHash)
    {
        BCryptDestroyHash(hHash);
    }

    if (hKeySymmetricKey)
    {
        BCryptDestroyKey(hKeySymmetricKey);
    }

    return hr;
}

extern "C" ThreadError otPlatRandomSecureGet(uint16_t aInputLength, uint8_t *aOutput, uint16_t *aOutputLength)
{
    // Just use the system-preferred random number generator algorithm
    NTSTATUS status =
        BCryptGenRandom(
            NULL,
            aOutput,
            (ULONG)aInputLength,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );
    if (status != 0)
    {
        return kThreadError_Failed;
    }

    *aOutputLength = aInputLength;

    return kThreadError_None;
}

inline uint16_t Swap16(uint16_t v)
{
    return
        (((v & 0x00ffU) << 8) & 0xff00) |
        (((v & 0xff00U) >> 8) & 0x00ff);
}

bool GetRlocAddr(_In_ otInstance* aInstance, _Out_ PIN6_ADDR addr)
{
    auto meshLocalPrefix = otGetMeshLocalPrefix(aInstance);
    if (!meshLocalPrefix) return false;
    memcpy_s(addr, sizeof(IN6_ADDR), meshLocalPrefix, 8);
    addr->u.Word[4] = Swap16(0x0000);
    addr->u.Word[5] = Swap16(0x00ff);
    addr->u.Word[6] = Swap16(0xfe00);
    addr->u.Word[7] = Swap16(otGetRloc16(aInstance));
    return true;
}

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        printf("Usage: border-router.exe <passphrase> <network name>\n");
        return E_INVALIDARG;
    }

    BorderRouter router;
    router.Start(argv[1], argv[2]);
}

BorderRouter::BorderRouter() :
    mCoapHandler(HandleCoapMessage, this),
    mApiInstance(otApiInit()),
    mThreadLeaderSocket(AF_INET6, HandleThreadSocketReceive, this),
    mCommissionerSocket(AF_INET, HandleCommissionerSocketReceive, this),
    mThreadJoinerRouterSocket(AF_INET6, HandleThreadSocketReceive, this)
{
    mCoap.AddResource(mCoapHandler);
}

BorderRouter::~BorderRouter()
{
    otApiFinalize(mApiInstance);
}

HRESULT BorderRouter::Start(const char* passPhrase, const char* networkName)
{
    WSADATA wsa;
    HRESULT hr = HRESULT_FROM_WIN32(WSAStartup(MAKEWORD(2, 2), &wsa));
    if (FAILED(hr))
    {
        return hr;
    }

    otDeviceList* deviceList = otEnumerateDevices(mApiInstance);
    if (deviceList->aDevicesLength < 1)
    {
        return HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    }

    GUID threadDeviceGuid = deviceList->aDevices[0];
    otInstance* deviceInstance = otInstanceInit(mApiInstance, &threadDeviceGuid);

    if (ThreadError::kThreadError_None != otGetLeaderRloc(deviceInstance, &mLeaderRloc))
    {
        return E_FAIL;
    }

    hr = mCommissionerSocket.Initialize();
    if (FAILED(hr))
    {
        return hr;
    }

    IN6_ADDR sin6Addr;
    if (!GetRlocAddr(deviceInstance, &sin6Addr))
    {
        printf("GetRlocAddr failed\n");
        return E_FAIL;
    }

    hr = mThreadLeaderSocket.Initialize();
    if (FAILED(hr))
    {
        return hr;
    }

    hr = mThreadJoinerRouterSocket.Initialize();
    if (FAILED(hr))
    {
        return hr;
    }

    CHAR szIpAddress[46] = { 0 };
    RtlIpv6AddressToStringA(&sin6Addr, szIpAddress);
    printf("Attempting to bind to IPv6 adress %s\n", szIpAddress);

    hr = mThreadLeaderSocket.Bind(0, &sin6Addr);
    if (FAILED(hr))
    {
        printf("mThreadLeaderSocket bind failed 0x%x\n", hr);
        return hr;
    }

    hr = mThreadJoinerRouterSocket.Bind(Thread::kCoapUdpPort, &sin6Addr);
    if (FAILED(hr))
    {
        printf("mThreadJoinerRouterSocket bind failed 0x%x\n", hr);
        return hr;
    }

    hr = mCommissionerSocket.Bind(DEFAULT_MESHCOP_PORT, nullptr);
    if (FAILED(hr))
    {
        printf("mCommissionerSocket bind failed 0x%x\n", hr);
        return hr;
    }

    uint8_t derivedKey[16];
    hr = GeneratePSKc(passPhrase, networkName, otGetExtendedPanId(deviceInstance), derivedKey);
    if (FAILED(hr))
    {
        printf("GeneratePSKc failed 0x%x\n", hr);
    }

    mDtls.SetPsk(derivedKey, sizeof(derivedKey));
    mDtls.Start(false, HandleDtlsReceive, HandleDtlsSend, this);

    mCommissionerSocket.Read();
    mThreadJoinerRouterSocket.Read();

    while (1)
    {
        SleepEx(INFINITE, TRUE);
    }

    return S_OK;
}

void BorderRouter::Stop()
{
    WSACleanup();
}

// static
void BorderRouter::HandleCommissionerSocketReceive(void *aContext, uint8_t *aBuf, DWORD aLength)
{
    static_cast<BorderRouter *>(aContext)->HandleCommissionerSocketReceive(aBuf, aLength);
}

void BorderRouter::HandleCommissionerSocketReceive(uint8_t *aBuf, DWORD aLength)
{
    // just got something from the commissioner socket, need to decrypt it (or continue the DTLS handshake)
    if (!mDtls.IsConnected())
    {
        // The DTLS server requires that we set some client ID, or the handshake will fail. The documentation
        // states that it is usually an ip/port pair (something that identifies the peer on the transport).
        // Set it here.
        sockaddr_storage currentPeer;
        mCommissionerSocket.GetLastPeer(&currentPeer);
        mDtls.SetClientId(reinterpret_cast<uint8_t*>(&currentPeer), sizeof(currentPeer));
    }
    mDtls.Receive(aBuf, static_cast<uint16_t>(aLength));
}

// static
void BorderRouter::HandleThreadSocketReceive(void *aContext, uint8_t *aBuf, DWORD aLength)
{
    static_cast<BorderRouter *>(aContext)->HandleThreadSocketReceive(aBuf, aLength);
}

void BorderRouter::HandleThreadSocketReceive(uint8_t* aBuf, DWORD aLength)
{
    printf("BorderRouter::HandleThreadSocketReceive called with length %d\n", aLength);
    // there is current no message that needs inspection by the border-router -- all messages
    // can be forwarded directly to the commissioner as is
    mDtls.Send(aBuf, static_cast<uint16_t>(aLength));
}

// static
void BorderRouter::HandleDtlsReceive(void * aContext, uint8_t * aBuf, uint16_t aLength)
{
    static_cast<BorderRouter *>(aContext)->HandleDtlsReceive(aBuf, aLength);
}

void BorderRouter::HandleDtlsReceive(uint8_t *aBuf, uint16_t aLength)
{
    printf("BorderRouter::HandleDtlsReceive called! The length is %d\n", aLength);
    mCoap.Receive(aBuf, aLength);
}

ThreadError BorderRouter::HandleDtlsSend(void* aContext, const uint8_t* aBuf, uint16_t aLength)
{
    return static_cast<BorderRouter *>(aContext)->HandleDtlsSend(aBuf, aLength);
}

ThreadError BorderRouter::HandleDtlsSend(const uint8_t* aBuf, uint16_t aLength)
{
    printf("BorderRouter::HandleDtlsSend called!\n");
    HRESULT hr = mCommissionerSocket.Reply(aBuf, aLength);
    if (FAILED(hr))
    {
        return ThreadError::kThreadError_Error;
    }
    else
    {
        return ThreadError::kThreadError_None;
    }
}

void BorderRouter::HandleCoapMessage(void* aContext, OffMesh::Coap::Header& aHeader,
                                     uint8_t* aMessage, uint16_t aLength, const char* aUriPath)
{
    static_cast<BorderRouter*>(aContext)->HandleCoapMessage(aHeader, aMessage, aLength, aUriPath);
}

void BorderRouter::HandleCoapMessage(OffMesh::Coap::Header& aRequestHeader, uint8_t* aBuf,
                                     uint16_t aLength, const char* aUriPath)
{
    printf("BorderRouter::HandleCoapMessage called with URI %s, length %d!\n", aUriPath, aLength);

    // Most of the messages are going to go over the CommPet socket, which is
    // bound to an ephermeral port and sends to 61631, but some (RLY_*) use the
    // management socket which is bound to 61631 and sends to an ephermeral port
    // (the thread stack chooses this ephermeral port, wheras we choose the port
    // on the CommPet socket)
    bool sendToJoinerRouter = false;

    const char* destinationUri = nullptr;
    if (strcmp(aUriPath, OPENTHREAD_URI_COMMISSIONER_PETITION) == 0)
    {
        destinationUri = OPENTHREAD_URI_LEADER_PETITION;
    }
    else if (strcmp(aUriPath, OPENTHREAD_URI_COMMISSIONER_KEEP_ALIVE) == 0)
    {
        destinationUri = OPENTHREAD_URI_LEADER_KEEP_ALIVE;
    }
    else if (strcmp(aUriPath, OPENTHREAD_URI_ACTIVE_GET) == 0 ||
             strcmp(aUriPath, OPENTHREAD_URI_ACTIVE_SET) == 0 ||
             strcmp(aUriPath, OPENTHREAD_URI_PENDING_GET) == 0 ||
             strcmp(aUriPath, OPENTHREAD_URI_PENDING_SET) == 0 ||
             strcmp(aUriPath, OPENTHREAD_URI_COMMISSIONER_SET) == 0 ||
             strcmp(aUriPath, OPENTHREAD_URI_COMMISSIONER_GET) == 0)
    {
        // these URIs don't need to be modified, send them as is
        destinationUri = aUriPath;
    }
    else if (strcmp(aUriPath, OPENTHREAD_URI_RELAY_TX) == 0)
    {
        // these URIs don't need to be modified, send them as is, but send
        // them to the joiner router
        destinationUri = aUriPath;
        sendToJoinerRouter = true;
    }
    else
    {
        printf("BorderRouter::HandleCoapMessage unknown URI received: %s, ignoring", aUriPath);
        return;
    }

    OffMesh::Coap::Header header;
    header.Init();
    header.SetVersion(1);
    header.SetType(aRequestHeader.GetType());
    header.SetCode(aRequestHeader.GetCode());
    header.SetMessageId(aRequestHeader.GetMessageId());
    header.SetToken(aRequestHeader.GetToken(), aRequestHeader.GetTokenLength());
    header.AppendUriPathOptions(destinationUri);
    header.Finalize();

    uint16_t requiredSize = header.GetLength() + aLength;
    auto messageBuffer = std::unique_ptr<uint8_t[]>(new (std::nothrow) uint8_t[requiredSize]);
    if (messageBuffer == nullptr)
    {
        // failed to alloc, return
        return;
    }

    memcpy_s(messageBuffer.get(), requiredSize, header.GetBytes(), header.GetLength());
    memcpy_s(messageBuffer.get() + header.GetLength(), aLength, aBuf, aLength);

    if (!sendToJoinerRouter)
    {
        printf("Sending over leader socket, destination URI is %s, header is:\n", destinationUri);
        printBuffer((char*)header.GetBytes(), header.GetLength());

        sockaddr_in6 threadLeaderAddress = { 0 };
        memcpy_s(&threadLeaderAddress.sin6_addr, sizeof(threadLeaderAddress.sin6_addr), &mLeaderRloc, sizeof(IN6_ADDR));
        threadLeaderAddress.sin6_family = AF_INET6;
        threadLeaderAddress.sin6_port = htons(Thread::kCoapUdpPort);

        CHAR szIpAddress[46] = { 0 };
        RtlIpv6AddressToStringA(&threadLeaderAddress.sin6_addr, szIpAddress);
        printf("Attempting to send to leader at IPv6 adress %s\n", szIpAddress);

        mThreadLeaderSocket.SendTo(messageBuffer.get(), requiredSize, &threadLeaderAddress);
        if (!mThreadLeaderSocket.IsReading())
        {
            mThreadLeaderSocket.Read();
        }
    }
    else
    {
        printf("Sending over joiner router socket, destination URI is %s, header is:\n", destinationUri);
        printBuffer((char*)header.GetBytes(), header.GetLength());
        printf("Message is:\n");
        printBuffer((char*)aBuf, aLength);

        mThreadJoinerRouterSocket.Reply(messageBuffer.get(), requiredSize, Thread::kCoapUdpPort);
    }
}
