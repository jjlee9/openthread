/*
 *  Copyright (c) 2016, Microsoft Corporation.
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
#include "otNodeApi.tmh"

typedef DWORD (*fp_otvmpOpenHandle)(HANDLE* phandle);
typedef VOID  (*fp_otvmpCloseHandle)(HANDLE handle);
typedef DWORD (*fp_otvmpAddVirtualBus)(HANDLE handle, ULONG* pBusNumber, ULONG* pIfIndex);
typedef DWORD (*fp_otvmpRemoveVirtualBus)(HANDLE handle, ULONG BusNumber);

fp_otvmpOpenHandle          otvmpOpenHandle = nullptr;
fp_otvmpCloseHandle         otvmpCloseHandle = nullptr;
fp_otvmpAddVirtualBus       otvmpAddVirtualBus = nullptr;
fp_otvmpRemoveVirtualBus    otvmpRemoveVirtualBus = nullptr;

HMODULE gVmpModule = nullptr;
HANDLE  gVmpHandle = nullptr;

ULONG gNextBusNumber = 1;

otApiInstance *gApiInstance = nullptr;

uint16_t GetCountOfInstances()
{
    auto aDeviceList = otEnumerateDevices(gApiInstance);
    uint16_t DeviceCount = aDeviceList == nullptr ? 0 : aDeviceList->aDevicesLength;
    otFreeMemory(aDeviceList);
    return DeviceCount;
}

void TryRemoveAllInstances()
{
    uint8_t tries = 0;
    while (GetCountOfInstances() != 0 && ++tries <= 3)
    {
        if (ERROR_SUCCESS == otvmpRemoveVirtualBus(gVmpHandle, 0))
            Sleep(1000);
        else Sleep(250);
    }
}

otApiInstance* GetApiInstance()
{
    if (gApiInstance == nullptr)
    {
        gApiInstance = otApiInit();
        if (gApiInstance == nullptr)
        {
            printf("otApiInit failed!\n");
            return nullptr;
        }

        gVmpModule = LoadLibrary(TEXT("otvmpapi.dll"));
        if (gVmpModule == nullptr)
        {
            printf("LoadLibrary(\"otvmpapi\") failed!\n");
            return nullptr;
        }

        otvmpOpenHandle       = (fp_otvmpOpenHandle)GetProcAddress(gVmpModule, "otvmpOpenHandle");
        otvmpCloseHandle      = (fp_otvmpCloseHandle)GetProcAddress(gVmpModule, "otvmpCloseHandle");
        otvmpAddVirtualBus    = (fp_otvmpAddVirtualBus)GetProcAddress(gVmpModule, "otvmpAddVirtualBus");
        otvmpRemoveVirtualBus = (fp_otvmpRemoveVirtualBus)GetProcAddress(gVmpModule, "otvmpRemoveVirtualBus");

        (VOID)otvmpOpenHandle(&gVmpHandle);
        if (gVmpHandle == nullptr)
        {
            printf("otvmpOpenHandle failed!\n");
            return nullptr;
        }

        // Make sure there aren't any interfaces left over
        TryRemoveAllInstances();
    }

    return gApiInstance;
}

void Unload()
{
    TryRemoveAllInstances();
    otvmpCloseHandle(gVmpHandle);
    otApiFinalize(gApiInstance);
}

int Hex2Bin(const char *aHex, uint8_t *aBin, uint16_t aBinLength)
{
    size_t hexLength = strlen(aHex);
    const char *hexEnd = aHex + hexLength;
    uint8_t *cur = aBin;
    uint8_t numChars = hexLength & 1;
    uint8_t byte = 0;

    if ((hexLength + 1) / 2 > aBinLength)
    {
        return -1;
    }

    while (aHex < hexEnd)
    {
        if ('A' <= *aHex && *aHex <= 'F')
        {
            byte |= 10 + (*aHex - 'A');
        }
        else if ('a' <= *aHex && *aHex <= 'f')
        {
            byte |= 10 + (*aHex - 'a');
        }
        else if ('0' <= *aHex && *aHex <= '9')
        {
            byte |= *aHex - '0';
        }
        else
        {
            return -1;
        }

        aHex++;
        numChars++;

        if (numChars >= 2)
        {
            numChars = 0;
            *cur++ = byte;
            byte = 0;
        }
        else
        {
            byte <<= 4;
        }
    }

    return static_cast<int>(cur - aBin);
}

typedef struct otNode
{
    uint32_t    mId;
    DWORD       mBusIndex;
    otInstance* mInstance;
} otNode;

const char* otDeviceRoleToString(otDeviceRole role)
{
    switch (role)
    {
    case kDeviceRoleOffline:  return "offline";
    case kDeviceRoleDisabled: return "disabled";
    case kDeviceRoleDetached: return "detached";
    case kDeviceRoleChild:    return "child";
    case kDeviceRoleRouter:   return "router";
    case kDeviceRoleLeader:   return "leader";
    default:                  return "invalid";
    }
}

void OTCALL otNodeStateChangedCallback(uint32_t aFlags, void *aContext)
{
    otNode* aNode = (otNode*)aContext;

    if ((aFlags & OT_NET_ROLE) != 0)
    {
        printf("%d: new role: %s\n", aNode->mId, otDeviceRoleToString(otGetDeviceRole(aNode->mInstance)));
    }
}

#define NUMBER_OF_TRIES 10

OTNODEAPI otNode* OTCALL otNodeInit(uint32_t id)
{
    auto ApiInstance = GetApiInstance();
    if (ApiInstance == nullptr)
    {
        printf("GetApiInstance failed!\n");
        return nullptr;
    }

    DWORD newBusIndex = gNextBusNumber;
    NET_IFINDEX ifIndex = {};
    int tries = 0;

    DWORD dwError;
    while ((dwError = otvmpAddVirtualBus(gVmpHandle, &newBusIndex, &ifIndex)) != ERROR_SUCCESS && ++tries <= NUMBER_OF_TRIES)
    {
        Sleep(500);
    }

    if (tries > NUMBER_OF_TRIES)
    {
        printf("otvmpAddVirtualBus failed, 0x%x!\n", dwError);
        return nullptr;
    }

    gNextBusNumber++;

    NET_LUID ifLuid = {};
    if (ERROR_SUCCESS != ConvertInterfaceIndexToLuid(ifIndex, &ifLuid))
    {
        printf("ConvertInterfaceIndexToLuid(%u) failed!\n", ifIndex);
        return nullptr;
    }

    GUID ifGuid = {};
    if (ERROR_SUCCESS != ConvertInterfaceLuidToGuid(&ifLuid, &ifGuid))
    {
        printf("ConvertInterfaceLuidToGuid failed!\n");
        return nullptr;
    }
    
    auto instance = otInstanceInit(ApiInstance, &ifGuid);
    if (instance == nullptr)
    {
        printf("otInstanceInit failed!\n");
        return nullptr;
    }

    otNode *node = new otNode();
    printf("%d: node created\n", id);

    node->mId = id;
    node->mBusIndex = newBusIndex;
    node->mInstance = instance;

    otSetStateChangedCallback(instance, otNodeStateChangedCallback, node);

    return node;
}

OTNODEAPI int32_t OTCALL otNodeFinalize(otNode* aNode)
{
    if (aNode != nullptr)
    {
        otSetStateChangedCallback(aNode->mInstance, nullptr, nullptr);
        otvmpRemoveVirtualBus(gVmpHandle, aNode->mBusIndex);
        delete aNode;
    }
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeSetMode(otNode* aNode, const char *aMode)
{
    printf("%d: mode %s\n", aNode->mId, aMode);

    otLinkModeConfig linkMode = {0};

    const char *index = aMode;
    while (*index)
    {
        switch (*index)
        {
        case 'r':
            linkMode.mRxOnWhenIdle = true;
            break;
        case 's':
            linkMode.mSecureDataRequests = true;
            break;
        case 'd':
            linkMode.mDeviceType = true;
            break;
        case 'n':
            linkMode.mNetworkData = true;
            break;
        }

        index++;
    }

    return otSetLinkMode(aNode->mInstance, linkMode);
}

OTNODEAPI int32_t OTCALL otNodeStart(otNode* aNode)
{
    printf("%d: start\n", aNode->mId);

    auto error = otInterfaceUp(aNode->mInstance);
    if (error != kThreadError_None) return error;
    return otThreadStart(aNode->mInstance);
}

OTNODEAPI int32_t OTCALL otNodeStop(otNode* aNode)
{
    printf("%d: stop\n", aNode->mId);

    (void)otThreadStop(aNode->mInstance);
    (void)otInterfaceDown(aNode->mInstance);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeClearWhitelist(otNode* aNode)
{
    printf("%d: whitelist clear\n", aNode->mId);

    otClearMacWhitelist(aNode->mInstance);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeEnableWhitelist(otNode* aNode)
{
    printf("%d: whitelist enable\n", aNode->mId);

    otEnableMacWhitelist(aNode->mInstance);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeDisableWhitelist(otNode* aNode)
{
    printf("%d: whitelist disable\n", aNode->mId);

    otDisableMacWhitelist(aNode->mInstance);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeAddWhitelist(otNode* aNode, const char *aExtAddr, int8_t aRssi)
{
    if (aRssi == 0)
        printf("%d: whitelist add %s\n", aNode->mId, aExtAddr);
    else printf("%d: whitelist add %s %d\n", aNode->mId, aExtAddr, aRssi);

    uint8_t extAddr[8];
    if (Hex2Bin(aExtAddr, extAddr, sizeof(extAddr)) != sizeof(extAddr))
        return kThreadError_Parse;

    if (aRssi == 0)
    {
        return otAddMacWhitelist(aNode->mInstance, extAddr);
    }
    else
    {
        return otAddMacWhitelistRssi(aNode->mInstance, extAddr, aRssi);
    }
}

OTNODEAPI int32_t OTCALL otNodeRemoveWhitelist(otNode* aNode, const char *aExtAddr)
{
    printf("%d: whitelist remove %s\n", aNode->mId, aExtAddr);

    uint8_t extAddr[8];
    if (Hex2Bin(aExtAddr, extAddr, sizeof(extAddr)) != sizeof(extAddr))
        return kThreadError_InvalidArgs;

    otRemoveMacWhitelist(aNode->mInstance, extAddr);
    return 0;
}

OTNODEAPI const char* OTCALL otNodeGetAddr16(otNode* aNode)
{
    char* str = (char*)malloc(6);
    sprintf_s(str, 6, "%04x", otGetRloc16(aNode->mInstance));
    printf("%d: rloc16\n%s\n", aNode->mId, str);
    return str;
}

OTNODEAPI const char* OTCALL otNodeGetAddr64(otNode* aNode)
{
    auto extAddr = otGetExtendedAddress(aNode->mInstance);
    char* str = (char*)malloc(18);
    for (int i = 0; i < 8; i++)
        sprintf_s(str + i * 2, 18 - (2 * i), "%02x", extAddr[i]);
    printf("%d: extaddr\n%s\n", aNode->mId, str);
    return str;
}

OTNODEAPI int32_t OTCALL otNodeSetChannel(otNode* aNode, uint8_t aChannel)
{
    printf("%d: channel %d\n", aNode->mId, aChannel);
    return otSetChannel(aNode->mInstance, aChannel);
}

OTNODEAPI uint32_t OTCALL otNodeGetKeySequence(otNode* aNode)
{
    auto result = otGetKeySequenceCounter(aNode->mInstance);
    printf("%d: key sequence\n%d\n", aNode->mId, result);
    return result;
}

OTNODEAPI int32_t OTCALL otNodeSetKeySequence(otNode* aNode, uint32_t aSequence)
{
    printf("%d: key sequence %d\n", aNode->mId, aSequence);
    otSetKeySequenceCounter(aNode->mInstance, aSequence);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeSetNetworkIdTimeout(otNode* aNode, uint8_t aTimeout)
{
    printf("%d: network id timeout %d\n", aNode->mId, aTimeout);
    otSetNetworkIdTimeout(aNode->mInstance, aTimeout);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeSetNetworkName(otNode* aNode, const char *aName)
{
    printf("%d: network name %s\n", aNode->mId, aName);
    return otSetNetworkName(aNode->mInstance, aName);
}

OTNODEAPI uint16_t OTCALL otNodeGetPanId(otNode* aNode)
{
    auto result = otGetPanId(aNode->mInstance);
    printf("%d: panid\n0x%04x\n", aNode->mId, result);
    return result;
}

OTNODEAPI int32_t OTCALL otNodeSetPanId(otNode* aNode, uint16_t aPanId)
{
    printf("%d: panid 0x%04x\n", aNode->mId, aPanId);
    return otSetPanId(aNode->mInstance, aPanId);
}

OTNODEAPI int32_t OTCALL otNodeSetRouterUpgradeThreshold(otNode* aNode, uint8_t aThreshold)
{
    printf("%d: router upgrade threshold %d\n", aNode->mId, aThreshold);
    otSetRouterUpgradeThreshold(aNode->mInstance, aThreshold);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeReleaseRouterId(otNode* aNode, uint8_t aRouterId)
{
    printf("%d: release router id %d\n", aNode->mId, aRouterId);
    return otReleaseRouterId(aNode->mInstance, aRouterId);
}

OTNODEAPI const char* OTCALL otNodeGetState(otNode* aNode)
{
    auto role = otGetDeviceRole(aNode->mInstance);
    auto result = _strdup(otDeviceRoleToString(role));
    printf("%d: state\n%s\n", aNode->mId, result);
    return result;
}

OTNODEAPI int32_t OTCALL otNodeSetState(otNode* aNode, const char *aState)
{
    printf("%d: state %s\n", aNode->mId, aState);

    if (strcmp(aState, "detached") == 0)
    {
        return otBecomeDetached(aNode->mInstance);
    }
    else if (strcmp(aState, "child") == 0)
    {
        return otBecomeChild(aNode->mInstance, kMleAttachAnyPartition);
    }
    else if (strcmp(aState, "router") == 0)
    {
        return otBecomeRouter(aNode->mInstance);
    }
    else if (strcmp(aState, "leader") == 0)
    {
        return otBecomeLeader(aNode->mInstance);
    }
    else
    {
        return kThreadError_InvalidArgs;
    }
}

OTNODEAPI uint32_t OTCALL otNodeGetTimeout(otNode* aNode)
{
    return otGetChildTimeout(aNode->mInstance);
}

OTNODEAPI int32_t OTCALL otNodeSetTimeout(otNode* aNode, uint32_t aTimeout)
{
    printf("%d: timeout %d\n", aNode->mId, aTimeout);
    otSetChildTimeout(aNode->mInstance, aTimeout);
    return 0;
}

OTNODEAPI uint8_t OTCALL otNodeGetWeight(otNode* aNode)
{
    return otGetLeaderWeight(aNode->mInstance);
}

OTNODEAPI int32_t OTCALL otNodeSetWeight(otNode* aNode, uint8_t aWeight)
{
    printf("%d: leader weight %d\n", aNode->mId, aWeight);
    otSetLocalLeaderWeight(aNode->mInstance, aWeight);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeAddIpAddr(otNode* aNode, const char *aAddr)
{
    printf("%d: add ipaddr %s\n", aNode->mId, aAddr);

    otNetifAddress aAddress;
    auto error = otIp6AddressFromString(aAddr, &aAddress.mAddress);
    if (error != kThreadError_None) return error;

    aAddress.mPrefixLength = 64;
    aAddress.mPreferredLifetime = 0xffffffff;
    aAddress.mValidLifetime = 0xffffffff;
    return otAddUnicastAddress(aNode->mInstance, &aAddress);
}

inline uint16_t Swap16(uint16_t v)
{
    return
        (((v & 0x00ffU) << 8) & 0xff00) |
        (((v & 0xff00U) >> 8) & 0x00ff);
}

OTNODEAPI const char* OTCALL otNodeGetAddrs(otNode* aNode)
{
    auto addrs = otGetUnicastAddresses(aNode->mInstance);
    if (addrs == nullptr) return nullptr;

    char* str = (char*)malloc(512);
    RtlZeroMemory(str, 512);

    char* cur = str;
    
    for (const otNetifAddress *addr = addrs; addr; addr = addr->mNext)
    {
        if (cur != str)
        {
            *cur = '\n';
            cur++;
        }

        cur += 
            sprintf_s(
                cur, 512 - (cur - str),
                "%x:%x:%x:%x:%x:%x:%x:%x",
                Swap16(addr->mAddress.mFields.m16[0]),
                Swap16(addr->mAddress.mFields.m16[1]),
                Swap16(addr->mAddress.mFields.m16[2]),
                Swap16(addr->mAddress.mFields.m16[3]),
                Swap16(addr->mAddress.mFields.m16[4]),
                Swap16(addr->mAddress.mFields.m16[5]),
                Swap16(addr->mAddress.mFields.m16[6]),
                Swap16(addr->mAddress.mFields.m16[7]));
    }

    otFreeMemory(addrs);
    
    printf("%d: ipaddr\n%s\n", aNode->mId, str);

    return str;
}

OTNODEAPI uint32_t OTCALL otNodeGetContextReuseDelay(otNode* aNode)
{
    return otGetContextIdReuseDelay(aNode->mInstance);
}

OTNODEAPI int32_t OTCALL otNodeSetContextReuseDelay(otNode* aNode, uint32_t aDelay)
{
    otSetContextIdReuseDelay(aNode->mInstance, aDelay);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeAddPrefix(otNode* aNode, const char *aPrefix, const char *aFlags, const char *aPreference)
{
    otBorderRouterConfig config = {0};
    char *prefixLengthStr;
    char *endptr;

    if ((prefixLengthStr = (char*)strchr(aPrefix, '/')) == NULL)
        return kThreadError_InvalidArgs;

    *prefixLengthStr++ = '\0';
    
    auto error = otIp6AddressFromString(aPrefix, &config.mPrefix.mPrefix);
    if (error != kThreadError_None) return error;

    config.mPrefix.mLength = static_cast<uint8_t>(strtol(prefixLengthStr, &endptr, 0));
    
    if (*endptr != '\0') return kThreadError_Parse;
    
    const char *index = aFlags;
    while (*index)
    {
        switch (*index)
        {
        case 'p':
            config.mPreferred = true;
            break;
        case 'a':
            config.mSlaac = true;
            break;
        case 'd':
            config.mDhcp = true;
            break;
        case 'c':
            config.mConfigure = true;
            break;
        case 'r':
            config.mDefaultRoute = true;
            break;
        case 'o':
            config.mOnMesh = true;
            break;
        case 's':
            config.mStable = true;
            break;
        default:
            return kThreadError_InvalidArgs;
        }

        index++;
    }
    
    if (strcmp(aPreference, "high") == 0)
    {
        config.mPreference = 1;
    }
    else if (strcmp(aPreference, "med") == 0)
    {
        config.mPreference = 1;
    }
    else if (strcmp(aPreference, "low") == 0)
    {
        config.mPreference = -1;
    }
    else
    {
        return kThreadError_InvalidArgs;
    }

    return otAddBorderRouter(aNode->mInstance, &config);
}

OTNODEAPI int32_t OTCALL otNodeRemovePrefix(otNode* aNode, const char *aPrefix)
{
    struct otIp6Prefix prefix;
    char *prefixLengthStr;
    char *endptr;

    if ((prefixLengthStr = (char *)strchr(aPrefix, '/')) == NULL)
        return kThreadError_InvalidArgs;

    *prefixLengthStr++ = '\0';
    
    auto error = otIp6AddressFromString(aPrefix, &prefix.mPrefix);
    if (error != kThreadError_None) return error;

    prefix.mLength = static_cast<uint8_t>(strtol(prefixLengthStr, &endptr, 0));

    if (*endptr != '\0') return kThreadError_Parse;

    return otRemoveBorderRouter(aNode->mInstance, &prefix);
}

OTNODEAPI int32_t OTCALL otNodeAddRoute(otNode* aNode, const char *aPrefix, const char *aPreference)
{
    otExternalRouteConfig config = {0};
    char *prefixLengthStr;
    char *endptr;

    if ((prefixLengthStr = (char*)strchr(aPrefix, '/')) == NULL)
        return kThreadError_InvalidArgs;

    *prefixLengthStr++ = '\0';
    
    auto error = otIp6AddressFromString(aPrefix, &config.mPrefix.mPrefix);
    if (error != kThreadError_None) return error;

    config.mPrefix.mLength = static_cast<uint8_t>(strtol(prefixLengthStr, &endptr, 0));
    
    if (*endptr != '\0') return kThreadError_Parse;
    
    if (strcmp(aPreference, "high") == 0)
    {
        config.mPreference = 1;
    }
    else if (strcmp(aPreference, "med") == 0)
    {
        config.mPreference = 1;
    }
    else if (strcmp(aPreference, "low") == 0)
    {
        config.mPreference = -1;
    }
    else
    {
        return kThreadError_InvalidArgs;
    }

    return otAddExternalRoute(aNode->mInstance, &config);
}

OTNODEAPI int32_t OTCALL otNodeRemoveRoute(otNode* aNode, const char *aPrefix)
{
    struct otIp6Prefix prefix;
    char *prefixLengthStr;
    char *endptr;

    if ((prefixLengthStr = (char *)strchr(aPrefix, '/')) == NULL)
        return kThreadError_InvalidArgs;

    *prefixLengthStr++ = '\0';
    
    auto error = otIp6AddressFromString(aPrefix, &prefix.mPrefix);
    if (error != kThreadError_None) return error;

    prefix.mLength = static_cast<uint8_t>(strtol(prefixLengthStr, &endptr, 0));

    if (*endptr != '\0') return kThreadError_Parse;

    return otRemoveExternalRoute(aNode->mInstance, &prefix);
}

OTNODEAPI int32_t OTCALL otNodeRegisterNetdata(otNode* aNode)
{
    return otSendServerData(aNode->mInstance);
}

OTNODEAPI int32_t OTCALL otNodeEnergyScan(otNode* aNode, uint32_t aMask, uint8_t aCount, uint16_t aPeriod, uint16_t aDuration, const char *aAddr)
{
    UNREFERENCED_PARAMETER(aNode);
    UNREFERENCED_PARAMETER(aMask);
    UNREFERENCED_PARAMETER(aCount);
    UNREFERENCED_PARAMETER(aPeriod);
    UNREFERENCED_PARAMETER(aDuration);
    UNREFERENCED_PARAMETER(aAddr);
    return kThreadError_NotImplemented;
}

OTNODEAPI int32_t OTCALL otNodePanIdQuery(otNode* aNode, uint16_t aPanId, uint32_t aMask, const char *aAddr)
{
    UNREFERENCED_PARAMETER(aNode);
    UNREFERENCED_PARAMETER(aPanId);
    UNREFERENCED_PARAMETER(aMask);
    UNREFERENCED_PARAMETER(aAddr);
    return kThreadError_NotImplemented;
}

OTNODEAPI const char* OTCALL otNodeScan(otNode* aNode)
{
    UNREFERENCED_PARAMETER(aNode);
    return nullptr;
}

OTNODEAPI int32_t OTCALL otNodePing(otNode* aNode, const char *aAddr, uint32_t aSize)
{
    UNREFERENCED_PARAMETER(aNode);
    UNREFERENCED_PARAMETER(aAddr);
    UNREFERENCED_PARAMETER(aSize);
    return FALSE;
}
