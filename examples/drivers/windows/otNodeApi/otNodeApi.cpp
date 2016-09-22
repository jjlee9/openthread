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
#include "otNodeApi.tmh"

#define GUID_FORMAT "{%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}"
#define GUID_ARG(guid) guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]

typedef DWORD (*fp_otvmpOpenHandle)(HANDLE* phandle);
typedef VOID  (*fp_otvmpCloseHandle)(HANDLE handle);
typedef DWORD (*fp_otvmpAddVirtualBus)(HANDLE handle, ULONG* pBusNumber, ULONG* pIfIndex);
typedef DWORD (*fp_otvmpRemoveVirtualBus)(HANDLE handle, ULONG BusNumber);
typedef DWORD (*fp_otvmpSetAdapterTopologyGuid)(HANDLE handle, DWORD BusNumber, const GUID* pTopologyGuid);

fp_otvmpOpenHandle              otvmpOpenHandle = nullptr;
fp_otvmpCloseHandle             otvmpCloseHandle = nullptr;
fp_otvmpAddVirtualBus           otvmpAddVirtualBus = nullptr;
fp_otvmpRemoveVirtualBus        otvmpRemoveVirtualBus = nullptr;
fp_otvmpSetAdapterTopologyGuid  otvmpSetAdapterTopologyGuid = nullptr;

HMODULE gVmpModule = nullptr;
HANDLE  gVmpHandle = nullptr;

ULONG gNextBusNumber = 1;
GUID gTopologyGuid = {0};

volatile LONG gNumberOfInterfaces = 0;

otApiInstance *gApiInstance = nullptr;

otApiInstance* GetApiInstance()
{
    if (gApiInstance == nullptr)
    {
        gApiInstance = otApiInit();
        if (gApiInstance == nullptr)
        {
            printf("otApiInit failed!\r\n");
            return nullptr;
        }

        gVmpModule = LoadLibrary(TEXT("otvmpapi.dll"));
        if (gVmpModule == nullptr)
        {
            printf("LoadLibrary(\"otvmpapi\") failed!\r\n");
            return nullptr;
        }

        otvmpOpenHandle             = (fp_otvmpOpenHandle)GetProcAddress(gVmpModule, "otvmpOpenHandle");
        otvmpCloseHandle            = (fp_otvmpCloseHandle)GetProcAddress(gVmpModule, "otvmpCloseHandle");
        otvmpAddVirtualBus          = (fp_otvmpAddVirtualBus)GetProcAddress(gVmpModule, "otvmpAddVirtualBus");
        otvmpRemoveVirtualBus       = (fp_otvmpRemoveVirtualBus)GetProcAddress(gVmpModule, "otvmpRemoveVirtualBus");
        otvmpSetAdapterTopologyGuid = (fp_otvmpSetAdapterTopologyGuid)GetProcAddress(gVmpModule, "otvmpSetAdapterTopologyGuid");

        if (otvmpOpenHandle == nullptr) printf("otvmpOpenHandle is null!\r\n");
        if (otvmpCloseHandle == nullptr) printf("otvmpCloseHandle is null!\r\n");
        if (otvmpAddVirtualBus == nullptr) printf("otvmpAddVirtualBus is null!\r\n");
        if (otvmpRemoveVirtualBus == nullptr) printf("otvmpRemoveVirtualBus is null!\r\n");
        if (otvmpSetAdapterTopologyGuid == nullptr) printf("otvmpSetAdapterTopologyGuid is null!\r\n");

        (VOID)otvmpOpenHandle(&gVmpHandle);
        if (gVmpHandle == nullptr)
        {
            printf("otvmpOpenHandle failed!\r\n");
            return nullptr;
        }

        auto status = UuidCreate(&gTopologyGuid);
        if (status != NO_ERROR)
        {
            printf("UuidCreate failed, 0x%x!\r\n", status);
            return nullptr;
        }

        auto offset = getenv("INSTANCE");
        if (offset)
        {
            gNextBusNumber = (atoi(offset) * 32) % 1000 + 1;
        }
        else
        {
            srand(gTopologyGuid.Data1);
            gNextBusNumber = rand() % 1000 + 1;
        }

        printf("New topology created\r\n" GUID_FORMAT " [%d]\r\n\r\n", GUID_ARG(gTopologyGuid), gNextBusNumber);
    }

    return gApiInstance;
}

void Unload()
{
    if (gNumberOfInterfaces != 0)
    {
        printf("Unloaded with %d outstanding nodes!\r\n", gNumberOfInterfaces);
    }

    if (gApiInstance)
    {
        if (gVmpHandle != nullptr)
        {
            otvmpCloseHandle(gVmpHandle);
            gVmpHandle = nullptr;
        }

        if (gVmpModule != nullptr)
        {
            CloseHandle(gVmpModule);
            gVmpModule = nullptr;
        }

        otApiFinalize(gApiInstance);
        gApiInstance = nullptr;

        printf("Topology destroyed\r\n");
    }
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
    HANDLE      mEnergyScanEvent;
    HANDLE      mPanIdConflictEvent;
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
        printf("%d: new role: %s\r\n", aNode->mId, otDeviceRoleToString(otGetDeviceRole(aNode->mInstance)));
    }
}

OTNODEAPI int32_t OTCALL otNodeLog(const char *aMessage)
{
    LogInfo(OT_API, "%s", aMessage);
    return 0;
}

OTNODEAPI otNode* OTCALL otNodeInit(uint32_t id)
{
    auto ApiInstance = GetApiInstance();
    if (ApiInstance == nullptr)
    {
        printf("GetApiInstance failed!\r\n");
        return nullptr;
    }

    DWORD newBusIndex;
    NET_IFINDEX ifIndex = {};
    
    DWORD dwError;
    DWORD tries = 0;
    while (tries < 1000)
    {
        newBusIndex = (gNextBusNumber + tries) % 1000;
        if (newBusIndex == 0) newBusIndex++;

        dwError = otvmpAddVirtualBus(gVmpHandle, &newBusIndex, &ifIndex);
        if (dwError == ERROR_SUCCESS)
        {
            gNextBusNumber = newBusIndex + 1;
            break;
        }
        else if (dwError == ERROR_INVALID_PARAMETER || dwError == ERROR_FILE_NOT_FOUND)
        {
            tries++;
        }
        else
        {
            printf("otvmpAddVirtualBus failed, 0x%x!\r\n", dwError);
            return nullptr;
        }
    }

    if (tries == 1000)
    {
        printf("otvmpAddVirtualBus failed to find an empty bus!\r\n");
        return nullptr;
    }

    if ((dwError = otvmpSetAdapterTopologyGuid(gVmpHandle, newBusIndex, &gTopologyGuid)) != ERROR_SUCCESS)
    {
        printf("otvmpSetAdapterTopologyGuid failed, 0x%x!\r\n", dwError);
        otvmpRemoveVirtualBus(gVmpHandle, newBusIndex);
        return nullptr;
    }

    NET_LUID ifLuid = {};
    if (ERROR_SUCCESS != ConvertInterfaceIndexToLuid(ifIndex, &ifLuid))
    {
        printf("ConvertInterfaceIndexToLuid(%u) failed!\r\n", ifIndex);
        otvmpRemoveVirtualBus(gVmpHandle, newBusIndex);
        return nullptr;
    }

    GUID ifGuid = {};
    if (ERROR_SUCCESS != ConvertInterfaceLuidToGuid(&ifLuid, &ifGuid))
    {
        printf("ConvertInterfaceLuidToGuid failed!\r\n");
        otvmpRemoveVirtualBus(gVmpHandle, newBusIndex);
        return nullptr;
    }
    
    auto instance = otInstanceInit(ApiInstance, &ifGuid);
    if (instance == nullptr)
    {
        printf("otInstanceInit failed!\r\n");
        otvmpRemoveVirtualBus(gVmpHandle, newBusIndex);
        return nullptr;
    }

    InterlockedIncrement(&gNumberOfInterfaces);

    GUID DeviceGuid = otGetDeviceGuid(instance);
    uint32_t Compartment = otGetCompartmentId(instance);

    otNode *node = new otNode();
    printf("%d: New Device " GUID_FORMAT " in compartment %d\r\n", id, GUID_ARG(DeviceGuid), Compartment);

    node->mId = id;
    node->mBusIndex = newBusIndex;
    node->mInstance = instance;

    node->mEnergyScanEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    node->mPanIdConflictEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);

    otSetStateChangedCallback(instance, otNodeStateChangedCallback, node);

    return node;
}

OTNODEAPI int32_t OTCALL otNodeFinalize(otNode* aNode)
{
    if (aNode != nullptr)
    {
        printf("%d: Removing Device\r\n", aNode->mId);

        CloseHandle(aNode->mPanIdConflictEvent);
        CloseHandle(aNode->mEnergyScanEvent);
        otSetStateChangedCallback(aNode->mInstance, nullptr, nullptr);
        otvmpRemoveVirtualBus(gVmpHandle, aNode->mBusIndex);
        delete aNode;
        
        if (0 == InterlockedDecrement(&gNumberOfInterfaces))
        {
            Unload();
        }
    }
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeSetMode(otNode* aNode, const char *aMode)
{
    printf("%d: mode %s\r\n", aNode->mId, aMode);

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
    printf("%d: start\r\n", aNode->mId);

    auto error = otInterfaceUp(aNode->mInstance);
    if (error != kThreadError_None) return error;
    return otThreadStart(aNode->mInstance);
}

OTNODEAPI int32_t OTCALL otNodeStop(otNode* aNode)
{
    printf("%d: stop\r\n", aNode->mId);

    (void)otThreadStop(aNode->mInstance);
    (void)otInterfaceDown(aNode->mInstance);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeClearWhitelist(otNode* aNode)
{
    printf("%d: whitelist clear\r\n", aNode->mId);

    otClearMacWhitelist(aNode->mInstance);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeEnableWhitelist(otNode* aNode)
{
    printf("%d: whitelist enable\r\n", aNode->mId);

    otEnableMacWhitelist(aNode->mInstance);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeDisableWhitelist(otNode* aNode)
{
    printf("%d: whitelist disable\r\n", aNode->mId);

    otDisableMacWhitelist(aNode->mInstance);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeAddWhitelist(otNode* aNode, const char *aExtAddr, int8_t aRssi)
{
    if (aRssi == 0)
        printf("%d: whitelist add %s\r\n", aNode->mId, aExtAddr);
    else printf("%d: whitelist add %s %d\r\n", aNode->mId, aExtAddr, aRssi);

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
    printf("%d: whitelist remove %s\r\n", aNode->mId, aExtAddr);

    uint8_t extAddr[8];
    if (Hex2Bin(aExtAddr, extAddr, sizeof(extAddr)) != sizeof(extAddr))
        return kThreadError_InvalidArgs;

    otRemoveMacWhitelist(aNode->mInstance, extAddr);
    return 0;
}

OTNODEAPI uint16_t OTCALL otNodeGetAddr16(otNode* aNode)
{
    auto result = otGetRloc16(aNode->mInstance);
    printf("%d: rloc16\r\n%04x\r\n", aNode->mId, result);
    return result;
}

OTNODEAPI const char* OTCALL otNodeGetAddr64(otNode* aNode)
{
    auto extAddr = otGetExtendedAddress(aNode->mInstance);
    char* str = (char*)malloc(18);
    for (int i = 0; i < 8; i++)
        sprintf_s(str + i * 2, 18 - (2 * i), "%02x", extAddr[i]);
    printf("%d: extaddr\r\n%s\r\n", aNode->mId, str);
    return str;
}

OTNODEAPI int32_t OTCALL otNodeSetChannel(otNode* aNode, uint8_t aChannel)
{
    printf("%d: channel %d\r\n", aNode->mId, aChannel);
    return otSetChannel(aNode->mInstance, aChannel);
}

OTNODEAPI uint32_t OTCALL otNodeGetKeySequence(otNode* aNode)
{
    auto result = otGetKeySequenceCounter(aNode->mInstance);
    printf("%d: key sequence\r\n%d\r\n", aNode->mId, result);
    return result;
}

OTNODEAPI int32_t OTCALL otNodeSetKeySequence(otNode* aNode, uint32_t aSequence)
{
    printf("%d: key sequence %d\r\n", aNode->mId, aSequence);
    otSetKeySequenceCounter(aNode->mInstance, aSequence);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeSetNetworkIdTimeout(otNode* aNode, uint8_t aTimeout)
{
    printf("%d: network id timeout %d\r\n", aNode->mId, aTimeout);
    otSetNetworkIdTimeout(aNode->mInstance, aTimeout);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeSetNetworkName(otNode* aNode, const char *aName)
{
    printf("%d: network name %s\r\n", aNode->mId, aName);
    return otSetNetworkName(aNode->mInstance, aName);
}

OTNODEAPI uint16_t OTCALL otNodeGetPanId(otNode* aNode)
{
    auto result = otGetPanId(aNode->mInstance);
    printf("%d: panid\r\n0x%04x\r\n", aNode->mId, result);
    return result;
}

OTNODEAPI int32_t OTCALL otNodeSetPanId(otNode* aNode, uint16_t aPanId)
{
    printf("%d: panid 0x%04x\r\n", aNode->mId, aPanId);
    return otSetPanId(aNode->mInstance, aPanId);
}

OTNODEAPI int32_t OTCALL otNodeSetRouterUpgradeThreshold(otNode* aNode, uint8_t aThreshold)
{
    printf("%d: router upgrade threshold %d\r\n", aNode->mId, aThreshold);
    otSetRouterUpgradeThreshold(aNode->mInstance, aThreshold);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeReleaseRouterId(otNode* aNode, uint8_t aRouterId)
{
    printf("%d: release router id %d\r\n", aNode->mId, aRouterId);
    return otReleaseRouterId(aNode->mInstance, aRouterId);
}

OTNODEAPI const char* OTCALL otNodeGetState(otNode* aNode)
{
    auto role = otGetDeviceRole(aNode->mInstance);
    auto result = _strdup(otDeviceRoleToString(role));
    printf("%d: state\r\n%s\r\n", aNode->mId, result);
    return result;
}

OTNODEAPI int32_t OTCALL otNodeSetState(otNode* aNode, const char *aState)
{
    printf("%d: state %s\r\n", aNode->mId, aState);

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
    printf("%d: timeout %d\r\n", aNode->mId, aTimeout);
    otSetChildTimeout(aNode->mInstance, aTimeout);
    return 0;
}

OTNODEAPI uint8_t OTCALL otNodeGetWeight(otNode* aNode)
{
    return otGetLeaderWeight(aNode->mInstance);
}

OTNODEAPI int32_t OTCALL otNodeSetWeight(otNode* aNode, uint8_t aWeight)
{
    printf("%d: leader weight %d\r\n", aNode->mId, aWeight);
    otSetLocalLeaderWeight(aNode->mInstance, aWeight);
    return 0;
}

OTNODEAPI int32_t OTCALL otNodeAddIpAddr(otNode* aNode, const char *aAddr)
{
    printf("%d: add ipaddr %s\r\n", aNode->mId, aAddr);

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
    
    printf("%d: ipaddr\r\n%s\r\n", aNode->mId, str);

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

void OTCALL otNodeCommissionerEnergyReportCallback(uint32_t aChannelMask, const uint8_t *aEnergyList, uint8_t aEnergyListLength, void *aContext)
{
    otNode* aNode = (otNode*)aContext;

    printf("Energy: 0x%08x\r\n", aChannelMask);
    for (uint8_t i = 0; i < aEnergyListLength; i++)
        printf("%d ", aEnergyList[i]);
    printf("\r\n");

    SetEvent(aNode->mEnergyScanEvent);
}

OTNODEAPI int32_t OTCALL otNodeEnergyScan(otNode* aNode, uint32_t aMask, uint8_t aCount, uint16_t aPeriod, uint16_t aDuration, const char *aAddr)
{
    printf("%d: energy scan 0x%x %d %d %d %s\r\n", aNode->mId, aMask, aCount, aPeriod, aDuration, aAddr);

    otIp6Address address = {0};
    auto error = otIp6AddressFromString(aAddr, &address);
    if (error != kThreadError_None)
    {
        printf("otIp6AddressFromString(%s) failed, 0x%x!\r\n", aAddr, error);
        return error;
    }
    
    ResetEvent(aNode->mEnergyScanEvent);

    error = otCommissionerEnergyScan(aNode->mInstance, aMask, aCount, aPeriod, aDuration, &address, otNodeCommissionerEnergyReportCallback, aNode);
    if (error != kThreadError_None)
    {
        printf("otCommissionerEnergyScan failed, 0x%x!\r\n", error);
        return error;
    }

    return WaitForSingleObject(aNode->mEnergyScanEvent, 8000) == WAIT_OBJECT_0 ? kThreadError_None : kThreadError_NotFound;
}

void OTCALL otNodeCommissionerPanIdConflictCallback(uint16_t aPanId, uint32_t aChannelMask, void *aContext)
{
    otNode* aNode = (otNode*)aContext;
    printf("Conflict: 0x%04x, 0x%08x\r\n", aPanId, aChannelMask);
    SetEvent(aNode->mPanIdConflictEvent);
}

OTNODEAPI int32_t OTCALL otNodePanIdQuery(otNode* aNode, uint16_t aPanId, uint32_t aMask, const char *aAddr)
{
    printf("%d: panid query 0x%04x 0x%x %s\r\n", aNode->mId, aPanId, aMask, aAddr);

    otIp6Address address = {0};
    auto error = otIp6AddressFromString(aAddr, &address);
    if (error != kThreadError_None)
    {
        printf("otIp6AddressFromString(%s) failed, 0x%x!\r\n", aAddr, error);
        return error;
    }
    
    ResetEvent(aNode->mPanIdConflictEvent);

    error = otCommissionerPanIdQuery(aNode->mInstance, aPanId, aMask, &address, otNodeCommissionerPanIdConflictCallback, aNode);
    if (error != kThreadError_None)
    {
        printf("otCommissionerPanIdQuery failed, 0x%x!\r\n", error);
        return error;
    }

    return WaitForSingleObject(aNode->mPanIdConflictEvent, 8000) == WAIT_OBJECT_0 ? kThreadError_None : kThreadError_NotFound;
}

OTNODEAPI const char* OTCALL otNodeScan(otNode* aNode)
{
    UNREFERENCED_PARAMETER(aNode);
    return nullptr;
}

OTNODEAPI uint32_t OTCALL otNodePing(otNode* aNode, const char *aAddr, uint16_t aSize)
{
    // Convert string to destination address
    otIp6Address otDestinationAddress = {0};
    auto error = otIp6AddressFromString(aAddr, &otDestinationAddress);
    if (error != kThreadError_None)
    {
        printf("otIp6AddressFromString(%s) failed!\r\n", aAddr);
        return 0;
    }
    
    // Get ML-EID as source address for ping
    auto otSourceAddress = otGetMeshLocalEid(aNode->mInstance);

    sockaddr_in6 SourceAddress = { AF_INET6, 0 };
    sockaddr_in6 DestinationAddress = { AF_INET6, 0 };

    memcpy(&SourceAddress.sin6_addr, otSourceAddress, sizeof(IN6_ADDR));
    memcpy(&DestinationAddress.sin6_addr, &otDestinationAddress, sizeof(IN6_ADDR));

    otFreeMemory(otSourceAddress);
    otSourceAddress = nullptr;
    
    // Put the current thead in the correct compartment
    bool RevertCompartmentOnExit = false;
    ULONG OriginalCompartmentID = GetCurrentThreadCompartmentId();
    if (OriginalCompartmentID != otGetCompartmentId(aNode->mInstance))
    {
        DWORD dwError = ERROR_SUCCESS;
        if ((dwError = SetCurrentThreadCompartmentId(otGetCompartmentId(aNode->mInstance))) != ERROR_SUCCESS)
        {
            printf("SetCurrentThreadCompartmentId failed, 0x%x\r\n", dwError);
        }
        RevertCompartmentOnExit = true;
    }

    auto SendBuffer = (PUCHAR)malloc(aSize);

    uint32_t aRecvSize = sizeof(ICMP_ECHO_REPLY) + aSize + MAX_OPT_SIZE;
    auto RecvBuffer = (PUCHAR)malloc(aRecvSize);

    // Initialize the send buffer pattern.
    for (uint32_t i = 0; i < aSize; i++)
        SendBuffer[i] = (char)('a' + (i % 23));

    DWORD numberOfReplies = 0;

    printf("%d: ping %s\r\n", aNode->mId, aAddr);

    // Get an ICMP handle
    auto IcmpHandle = Icmp6CreateFile();
    if (IcmpHandle == INVALID_HANDLE_VALUE)
    {
        printf("Icmp6CreateFile failed!\r\n");
        goto exit;
    }

    // Send the Echo Request
    numberOfReplies = 
        Icmp6SendEcho2(
            IcmpHandle,
            nullptr,
            nullptr,
            nullptr,
            &SourceAddress,
            &DestinationAddress,
            SendBuffer,
            aSize,
            nullptr,
            RecvBuffer,
            aRecvSize,
            4000 // Timeout
            );

    if (numberOfReplies == 0)
    {
        auto LastError = GetLastError();
        if (LastError == IP_REQ_TIMED_OUT)
        {
            printf("no reply(s)\r\n");
        }
        else printf("error: 0x%x\r\n", LastError);
    }
    else
    {    
        printf("%d reply(s)\r\n", numberOfReplies);

        //ICMPV6_ECHO_REPLY* Reply = (ICMPV6_ECHO_REPLY*)RecvBuffer;
    }

exit:
    
    // Revert the comparment if necessary
    if (RevertCompartmentOnExit)
    {
        (VOID)SetCurrentThreadCompartmentId(OriginalCompartmentID);
    }

    free(RecvBuffer);
    free(SendBuffer);

    IcmpCloseHandle(IcmpHandle);

    return numberOfReplies;
}
