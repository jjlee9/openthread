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
 *  This file defines a node interface for openthread.h to be used for certification tests
 */

#ifndef OTNODE_H_
#define OTNODE_H_

#include <openthread.h>

#ifndef OTNODEAPI
#define OTNODEAPI __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Represents a virtual node for an openthread interface
 */
typedef struct otNode otNode;

/**
 * Logs a WPP message
 */
OTNODEAPI int32_t OT_CALL otNodeLog(const char *aMessage);

/**
 * Allocates a new virtual node
 */
OTNODEAPI otNode* OT_CALL otNodeInit(uint32_t id);

/**
 * Frees a node
 */
OTNODEAPI int32_t OT_CALL otNodeFinalize(otNode* aNode);

/**
 * Sets the link mode
 */
OTNODEAPI int32_t OT_CALL otNodeSetMode(otNode* aNode, const char *aMode);

/**
 * Starts the thread interface
 */
OTNODEAPI int32_t OT_CALL otNodeInterfaceUp(otNode* aNode);

/**
 * Stops the thread interface
 */
OTNODEAPI int32_t OT_CALL otNodeInterfaceDown(otNode* aNode);

/**
 * Starts the thread logic
 */
OTNODEAPI int32_t OT_CALL otNodeThreadStart(otNode* aNode);

/**
 * Stops the thread logic
 */
OTNODEAPI int32_t OT_CALL otNodeThreadStop(otNode* aNode);

/**
 * Starts the commissioner logic
 */
OTNODEAPI int32_t OT_CALL otNodeCommissionerStart(otNode* aNode);

/**
 * Adds a new joiner to the list for commissioning
 */
OTNODEAPI int32_t OT_CALL otNodeCommissionerJoinerAdd(otNode* aNode, const char *aExtAddr, const char *aPSKd);

/**
 * Stops the commissioner logic
 */
OTNODEAPI int32_t OT_CALL otNodeCommissionerStop(otNode* aNode);

/**
 * Starts the joiner logic
 */
OTNODEAPI int32_t OT_CALL otNodeJoinerStart(otNode* aNode, const char *aPSKd, const char *aProvisioningUrl);

/**
 * Clears the node's whitelist
 */
OTNODEAPI int32_t OT_CALL otNodeClearWhitelist(otNode* aNode);

/**
 * Enables the node's whitelist
 */
OTNODEAPI int32_t OT_CALL otNodeEnableWhitelist(otNode* aNode);

/**
 * Disables the node's whitelist
 */
OTNODEAPI int32_t OT_CALL otNodeDisableWhitelist(otNode* aNode);

/**
 * Adds an entry to the node's whitelist
 */
OTNODEAPI int32_t OT_CALL otNodeAddWhitelist(otNode* aNode, const char *aExtAddr, int8_t aRssi);

/**
 * Removes an entry to the node's whitelist
 */
OTNODEAPI int32_t OT_CALL otNodeRemoveWhitelist(otNode* aNode, const char *aExtAddr);

/**
 * Gets the node's short mac address (Rloc16)
 */
OTNODEAPI uint16_t OT_CALL otNodeGetAddr16(otNode* aNode);

/**
 * Gets the node's extended mac address
 */
OTNODEAPI const char* OT_CALL otNodeGetAddr64(otNode* aNode);

/**
 * Gets the node's hash mac address
 */
OTNODEAPI const char* OT_CALL otNodeGetHashMacAddress(otNode* aNode);

/**
 * Sets the channel for the node
 */
OTNODEAPI int32_t OT_CALL otNodeSetChannel(otNode* aNode, uint8_t aChannel);

/**
 * sets the node's master key
 */
OTNODEAPI int32_t OT_CALL otNodeSetMasterkey(otNode* aNode, const char *aMasterkey);

/**
 * Gets the node's master key
 */
OTNODEAPI const char* OT_CALL otNodeGetMasterkey(otNode* aNode);

/**
 * Gets the key sequance for the node
 */
OTNODEAPI uint32_t OT_CALL otNodeGetKeySequence(otNode* aNode);

/**
 * Sets the network id timeout for the node
 */
OTNODEAPI int32_t OT_CALL otNodeSetKeySequence(otNode* aNode, uint32_t aSequence);

/**
 * Sets the network id timeout for the node
 */
OTNODEAPI int32_t OT_CALL otNodeSetNetworkIdTimeout(otNode* aNode, uint8_t aTimeout);

/**
 * Sets the network name for the node
 */
OTNODEAPI int32_t OT_CALL otNodeSetNetworkName(otNode* aNode, const char *aName);

/**
 * Gets the pan id for the node
 */
OTNODEAPI uint16_t OT_CALL otNodeGetPanId(otNode* aNode);

/**
 * Sets the pan id for the node
 */
OTNODEAPI int32_t OT_CALL otNodeSetPanId(otNode* aNode, uint16_t aPanId);

/**
 * Sets the router upgrade threshold for the node
 */
OTNODEAPI int32_t OT_CALL otNodeSetRouterUpgradeThreshold(otNode* aNode, uint8_t aThreshold);

/**
 * Sets the router downgrade threshold for the node
 */
OTNODEAPI int32_t OT_CALL otNodeSetRouterDowngradeThreshold(otNode* aNode, uint8_t aThreshold);

/**
 * Releases a router id for the node
 */
OTNODEAPI int32_t OT_CALL otNodeReleaseRouterId(otNode* aNode, uint8_t aRouterId);

/**
 * Gets the node's state
 */
OTNODEAPI const char* OT_CALL otNodeGetState(otNode* aNode);

/**
 * Sets the node's state
 */
OTNODEAPI int32_t OT_CALL otNodeSetState(otNode* aNode, const char *aState);

/**
 * Gets the child timeout for the node
 */
OTNODEAPI uint32_t OT_CALL otNodeGetTimeout(otNode* aNode);

/**
 * Sets the child timeout for the node
 */
OTNODEAPI int32_t OT_CALL otNodeSetTimeout(otNode* aNode, uint32_t aTimeout);

/**
 * Gets the leader weight for the node
 */
OTNODEAPI uint8_t OT_CALL otNodeGetWeight(otNode* aNode);

/**
 * Sets the leader weight for the node
 */
OTNODEAPI int32_t OT_CALL otNodeSetWeight(otNode* aNode, uint8_t aWeight);

/**
 * Adds an IP address for the node
 */
OTNODEAPI int32_t OT_CALL otNodeAddIpAddr(otNode* aNode, const char *aAddr);

/**
 * Gets the IP address for the node
 */
OTNODEAPI const char* OT_CALL otNodeGetAddrs(otNode* aNode);

/**
 * Gets the context reuse delay for the node
 */
OTNODEAPI uint32_t OT_CALL otNodeGetContextReuseDelay(otNode* aNode);

/**
 * Sets the context reuse delay for the node
 */
OTNODEAPI int32_t OT_CALL otNodeSetContextReuseDelay(otNode* aNode, uint32_t aDelay);

/**
 * Adds an IP prefix for the node
 */
OTNODEAPI int32_t OT_CALL otNodeAddPrefix(otNode* aNode, const char *aPrefix, const char *aFlags, const char *aPreference);

/**
 * Removes an IP prefix from the node
 */
OTNODEAPI int32_t OT_CALL otNodeRemovePrefix(otNode* aNode, const char *aPrefix);

/**
 * Adds an IP route for the node
 */
OTNODEAPI int32_t OT_CALL otNodeAddRoute(otNode* aNode, const char *aPrefix, const char *aPreference);

/**
 * Removes an IP route from the node
 */
OTNODEAPI int32_t OT_CALL otNodeRemoveRoute(otNode* aNode, const char *aPrefix);

/**
 * Registers the net data for the node
 */
OTNODEAPI int32_t OT_CALL otNodeRegisterNetdata(otNode* aNode);

/**
 * Performs an energy scan for the node
 */
OTNODEAPI int32_t OT_CALL otNodeEnergyScan(otNode* aNode, uint32_t aMask, uint8_t aCount, uint16_t aPeriod, uint16_t aDuration, const char *aAddr);

/**
 * Performs a panid query for the node
 */
OTNODEAPI int32_t OT_CALL otNodePanIdQuery(otNode* aNode, uint16_t aPanId, uint32_t aMask, const char *aAddr);

/**
 * Performs an scan for the node
 */
OTNODEAPI const char* OT_CALL otNodeScan(otNode* aNode);

/**
 * Performs an scan for the node
 */
OTNODEAPI uint32_t OT_CALL otNodePing(otNode* aNode, const char *aAddr, uint16_t aSize, uint32_t aMinReplies);

/**
 * Sets the router selection jitter value for a node
 */
OTNODEAPI int32_t OT_CALL otNodeSetRouterSelectionJitter(otNode* aNode, uint8_t aRouterJitter);

/**
 * Sends the announce message for a node
 */
OTNODEAPI int32_t OT_CALL otNodeCommissionerAnnounceBegin(otNode* aNode, uint32_t aChannelMask, uint8_t aCount, uint16_t aPeriod, const char *aAddr);

/**
 * Sets the active dataset for a node
 */
OTNODEAPI int32_t OT_CALL otNodeSetActiveDataset(otNode* aNode, uint64_t aTimestamp, uint16_t aPanId = 0, uint16_t aChannel = 0);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // OTNODE_H_
