#!/usr/bin/python
#
#  Copyright (c) 2016, The OpenThread Authors.
#  All rights reserved.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are met:
#  1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. Neither the name of the copyright holder nor the
#     names of its contributors may be used to endorse or promote products
#     derived from this software without specific prior written permission.
#
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
#  POSSIBILITY OF SUCH DAMAGE.
#

import os
import sys
import time
if sys.platform != 'win32':
    import pexpect
else:
    import ctypes
import unittest

class Node:
    def __init__(self, nodeid):
        self.nodeid = nodeid
        self.verbose = int(float(os.getenv('VERBOSE', 0)))
        self.node_type = os.getenv('NODE_TYPE', 'sim')

        if self.node_type == 'soc':
            self.__init_soc(nodeid)
        elif self.node_type == 'ncp-sim':
            self.__init_ncp_sim(nodeid)
        elif self.node_type == 'win-sim':
            self.__init_win_sim(nodeid)
        else:
            self.__init_sim(nodeid)

        if self.verbose:
            self.pexpect.logfile_read = sys.stdout

        self.clear_whitelist()
        self.disable_whitelist()
        self.set_timeout(100)

    def __init_sim(self, nodeid):
        """ Initialize a simulation node. """
        if "OT_CLI_PATH" in os.environ.keys():
            cmd = os.environ['OT_CLI_PATH']
        elif "top_builddir" in os.environ.keys():
            srcdir = os.environ['top_builddir']
            cmd = '%s/examples/apps/cli/ot-cli' % srcdir
        else:
            cmd = './ot-cli'
        cmd += ' %d' % nodeid
        print ("%s" % cmd)

        self.pexpect = pexpect.spawn(cmd, timeout=2)
        self.Api = None

        # Add delay to ensure that the process is ready to receive commands.
        time.sleep(0.1)


    def __init_ncp_sim(self, nodeid):
        """ Initialize an NCP simulation node. """
        if "top_builddir" in os.environ.keys():
            builddir = os.environ['top_builddir']
            if "top_srcdir" in os.environ.keys():
                srcdir = os.environ['top_srcdir']
            else:
                srcdir = os.path.dirname(os.path.realpath(__file__))
                srcdir += "/../../.."
            cmd = 'python %s/tools/spinel-cli/spinel-cli.py -p %s/examples/apps/ncp/ot-ncp -n' % (srcdir, builddir)
        else:
            cmd = './ot-ncp'
        cmd += ' %d' % nodeid
        print ("%s" % cmd)
        
        self.pexpect = pexpect.spawn(cmd, timeout=2)
        self.Api = None

        time.sleep(0.1)
        self.pexpect.expect('spinel-cli >')
 
    def __init_soc(self, nodeid):
        """ Initialize a System-on-a-chip node connected via UART. """
        import fdpexpect
        serialPort = '/dev/ttyUSB%d' % ((nodeid-1)*2)
        self.pexpect = fdpexpect.fdspawn(os.open(serialPort, os.O_RDWR|os.O_NONBLOCK|os.O_NOCTTY))
        self.Api = None

    def __del__(self):
        if self.Api:
            self.Api.otNodeFinalize(self.otNode);
        else:
            if self.pexpect.isalive():
                self.send_command('exit')
                self.pexpect.expect(pexpect.EOF)
                self.pexpect.terminate()
                self.pexpect.close(force=True)

    def send_command(self, cmd):
        print ("%d: %s" % (self.nodeid, cmd))
        self.pexpect.sendline(cmd)

    def get_commands(self):
        self.send_command('?')
        self.pexpect.expect('Commands:')
        commands = []
        while True:
            i = self.pexpect.expect(['Done', '(\S+)'])
            if i != 0:
                commands.append(self.pexpect.match.groups()[0])
            else:
                break
        return commands

    def set_mode(self, mode):   
        if self.Api:
            if self.Api.otNodeSetMode(self.otNode, mode.encode('utf-8')) != 0:
                raise OSError("otNodeSetMode failed!");
        else:     
            cmd = 'mode ' + mode
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def debug(self, level):
        self.send_command('debug '+str(level))

    def start(self):
        if self.Api:
            if self.Api.otNodeStart(self.otNode) != 0:
                raise OSError("otNodeStart failed!");
        else:     
            self.send_command('ifconfig up')
            self.pexpect.expect('Done')
            self.send_command('thread start')
            self.pexpect.expect('Done')

    def stop(self):
        if self.Api:
            if self.Api.otNodeStop(self.otNode) != 0:
                raise OSError("otNodeStop failed!");
        else:     
            self.send_command('thread stop')
            self.pexpect.expect('Done')
            self.send_command('ifconfig down')
            self.pexpect.expect('Done')

    def clear_whitelist(self):
        if self.Api:
            if self.Api.otNodeClearWhitelist(self.otNode) != 0:
                raise OSError("otNodeClearWhitelist failed!");
        else:     
            self.send_command('whitelist clear')
            self.pexpect.expect('Done')

    def enable_whitelist(self):
        if self.Api:
            if self.Api.otNodeEnableWhitelist(self.otNode) != 0:
                raise OSError("otNodeEnableWhitelist failed!");
        else:     
            self.send_command('whitelist enable')
            self.pexpect.expect('Done')

    def disable_whitelist(self):
        if self.Api:
            if self.Api.otNodeDisableWhitelist(self.otNode) != 0:
                raise OSError("otNodeDisableWhitelist failed!");
        else:     
            self.send_command('whitelist disable')
            self.pexpect.expect('Done')

    def add_whitelist(self, addr, rssi=None):
        if self.Api:
            if rssi == None:
                rssi = 0;
            if self.Api.otNodeAddWhitelist(self.otNode, addr.encode('utf-8'), ctypes.c_byte(rssi)) != 0:
                raise OSError("otNodeAddWhitelist failed!");
        else:     
            cmd = 'whitelist add ' + addr
            if rssi != None:
                cmd += ' ' + str(rssi)
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def remove_whitelist(self, addr):
        if self.Api:
            if self.Api.otNodeRemoveWhitelist(self.otNode, addr.encode('utf-8')) != 0:
                raise OSError("otNodeRemoveWhitelist failed!");
        else:     
            cmd = 'whitelist remove ' + addr
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def get_addr16(self):
        if self.Api:
            return str(self.Api.otNodeGetAddr16(self.otNode));
        else:
            self.send_command('rloc16')
            i = self.pexpect.expect('([0-9a-fA-F]{4})')
            if i == 0:
                addr16 = int(self.pexpect.match.groups()[0], 16)
            self.pexpect.expect('Done')
            return addr16

    def get_addr64(self):
        if self.Api:
            return self.Api.otNodeGetAddr64(self.otNode).decode('utf-8');
        else:
            self.send_command('extaddr')
            i = self.pexpect.expect('([0-9a-fA-F]{16})')
            if i == 0:
                addr64 = self.pexpect.match.groups()[0].decode("utf-8")
            self.pexpect.expect('Done')
            return addr64

    def set_channel(self, channel):
        if self.Api:
            if self.Api.otNodeSetChannel(self.otNode, ctypes.c_ubyte(channel)) != 0:
                raise OSError("otNodeSetChannel failed!");
        else:     
            cmd = 'channel %d' % channel
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def get_key_sequence(self):
        if self.Api:
            return int(self.Api.otNodeGetKeySequence(self.otNode));
        else:
            self.send_command('keysequence')
            i = self.pexpect.expect('(\d+)\r\n')
            if i == 0:
                key_sequence = int(self.pexpect.match.groups()[0])
            self.pexpect.expect('Done')
            return key_sequence

    def set_key_sequence(self, key_sequence):
        if self.Api:
            if self.Api.otNodeSetKeySequence(self.otNode, ctypes.c_uint(key_sequence)) != 0:
                raise OSError("otNodeSetKeySequence failed!");
        else:     
            cmd = 'keysequence %d' % key_sequence
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def set_network_id_timeout(self, network_id_timeout):
        if self.Api:
            if self.Api.otNodeSetNetworkIdTimeout(self.otNode, ctypes.c_ubyte(key_sequence)) != 0:
                raise OSError("otNodeSetNetworkIdTimeout failed!");
        else:     
            cmd = 'networkidtimeout %d' % network_id_timeout
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def set_network_name(self, network_name):
        if self.Api:
            if self.Api.otNodeSetNetworkName(self.otNode, network_name.encode('utf-8')) != 0:
                raise OSError("otNodeSetNetworkName failed!");
        else:     
            cmd = 'networkname ' + network_name
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def get_panid(self):
        if self.Api:
            return int(self.Api.otNodeGetPanId(self.otNode));
        else:
            self.send_command('panid')
            i = self.pexpect.expect('([0-9a-fA-F]{16})')
            if i == 0:
                panid = self.pexpect.match.groups()[0]
            self.pexpect.expect('Done')

    def set_panid(self, panid):
        if self.Api:
            if self.Api.otNodeSetPanId(self.otNode, ctypes.c_ushort(panid)) != 0:
                raise OSError("otNodeSetPanId failed!");
        else:  
            cmd = 'panid %d' % panid
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def set_router_upgrade_threshold(self, threshold):
        if self.Api:
            if self.Api.otNodeSetRouterUpgradeThreshold(self.otNode, ctypes.c_ubyte(threshold)) != 0:
                raise OSError("otNodeSetRouterUpgradeThreshold failed!");
        else:  
            cmd = 'routerupgradethreshold %d' % threshold
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def release_router_id(self, router_id):
        if self.Api:
            if self.Api.otNodeReleaseRouterId(self.otNode, ctypes.c_ubyte(router_id)) != 0:
                raise OSError("otNodeReleaseRouterId failed!");
        else:  
            cmd = 'releaserouterid %d' % router_id
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def get_state(self):
        if self.Api:
            return self.Api.otNodeGetState(self.otNode).decode('utf-8');
        else:
            states = ['detached', 'child', 'router', 'leader']
            self.send_command('state')
            match = self.pexpect.expect(states)
            self.pexpect.expect('Done')
            return states[match]

    def set_state(self, state):
        if self.Api:
            if self.Api.otNodeSetState(self.otNode, state.encode('utf-8')) != 0:
                raise OSError("otNodeSetState failed!");
        else:  
            cmd = 'state ' + state
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def get_timeout(self):
        if self.Api:
            return int(self.Api.otNodeGetTimeout(self.otNode));
        else:
            self.send_command('childtimeout')
            i = self.pexpect.expect('(\d+)\r\n')
            if i == 0:
                timeout = self.pexpect.match.groups()[0]
            self.pexpect.expect('Done')
            return timeout

    def set_timeout(self, timeout):
        if self.Api:
            if self.Api.otNodeSetTimeout(self.otNode, ctypes.c_uint(timeout)) != 0:
                raise OSError("otNodeSetTimeout failed!");
        else:  
            cmd = 'childtimeout %d' % timeout
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def get_weight(self):
        if self.Api:
            return int(self.Api.otNodeGetWeight(self.otNode));
        else:
            self.send_command('leaderweight')
            i = self.pexpect.expect('(\d+)\r\n')
            if i == 0:
                weight = self.pexpect.match.groups()[0]
            self.pexpect.expect('Done')
            return weight

    def set_weight(self, weight):
        if self.Api:
            if self.Api.otNodeSetWeight(self.otNode, ctypes.c_ubyte(weight)) != 0:
                raise OSError("otNodeSetWeight failed!");
        else:  
            cmd = 'leaderweight %d' % weight
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def add_ipaddr(self, ipaddr):
        if self.Api:
            if self.Api.otNodeAddIpAddr(self.otNode, ipaddr.encode('utf-8')) != 0:
                raise OSError("otNodeAddIpAddr failed!");
        else:  
            cmd = 'ipaddr add ' + ipaddr
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def get_addrs(self):
        if self.Api:
            return str(self.Api.otNodeGetWeight(self.otNode)).split("\n");
        else:
            addrs = []
            self.send_command('ipaddr')

            while True:
                i = self.pexpect.expect(['(\S+:\S+)\r\n', 'Done'])
                if i == 0:
                    addrs.append(self.pexpect.match.groups()[0].decode("utf-8"))
                elif i == 1:
                    break

            return addrs

    def get_context_reuse_delay(self):
        if self.Api:
            return int(self.Api.otNodeGetContextReuseDelay(self.otNode));
        else:
            self.send_command('contextreusedelay')
            i = self.pexpect.expect('(\d+)\r\n')
            if i == 0:
                timeout = self.pexpect.match.groups()[0]
            self.pexpect.expect('Done')
            return timeout

    def set_context_reuse_delay(self, delay):
        if self.Api:
            if self.Api.otNodeSetContextReuseDelay(self.otNode, ctypes.c_uint(delay)) != 0:
                raise OSError("otNodeSetContextReuseDelay failed!");
        else:  
            cmd = 'contextreusedelay %d' % delay
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def add_prefix(self, prefix, flags, prf = 'med'):
        if self.Api:
            if self.Api.otNodeAddPrefix(self.otNode, prefix.encode('utf-8'), flags.encode('utf-8'), prf.encode('utf-8')) != 0:
                raise OSError("otNodeAddPrefix failed!");
        else:  
            cmd = 'prefix add ' + prefix + ' ' + flags + ' ' + prf
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def remove_prefix(self, prefix):
        if self.Api:
            if self.Api.otNodeRemovePrefix(self.otNode, prefix.encode('utf-8')) != 0:
                raise OSError("otNodeRemovePrefix failed!");
        else:  
            cmd = ' prefix remove ' + prefix
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def add_route(self, prefix, prf = 'med'):
        if self.Api:
            if self.Api.otNodeAddRoute(self.otNode, prefix.encode('utf-8'), prf.encode('utf-8')) != 0:
                raise OSError("otNodeAddRoute failed!");
        else:  
            cmd = 'route add ' + prefix + ' ' + prf
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def remove_route(self, prefix):
        if self.Api:
            if self.Api.otNodeRemoveRoute(self.otNode, prefix.encode('utf-8')) != 0:
                raise OSError("otNodeRemovePrefix failed!");
        else:  
            cmd = 'route remove ' + prefix
            self.send_command(cmd)
            self.pexpect.expect('Done')

    def register_netdata(self):
        if self.Api:
            if self.Api.otNodeRegisterNetdata(self.otNode) != 0:
                raise OSError("otNodeRegisterNetdata failed!");
        else:  
            self.send_command('netdataregister')
            self.pexpect.expect('Done')

    def energy_scan(self, mask, count, period, scan_duration, ipaddr):
        if self.Api:
            if self.Api.otNodeEnergyScan(self.otNode, ctypes.c_uint(mask), ctypes.c_ubyte(count), ctypes.c_ushort(period), ctypes.c_ushort(scan_duration), ctypes.cast(ipaddr, ctypes.c_char_p)) != 0:
                raise OSError("otNodeEnergyScan failed!");
        else:  
            cmd = 'commissioner energy ' + str(mask) + ' ' + str(count) + ' ' + str(period) + ' ' + str(scan_duration) + ' ' + ipaddr
            self.send_command(cmd)
            self.pexpect.expect('Energy:', timeout=8)

    def panid_query(self, panid, mask, ipaddr):
        if self.Api:
            if self.Api.otNodeEnergyScan(self.otNode, ctypes.c_ushort(panid), ctypes.c_uint(mask), ipaddr.encode('utf-8')) != 0:
                raise OSError("otNodeEnergyScan failed!");
        else:  
            cmd = 'commissioner panid ' + str(panid) + ' ' + str(mask) + ' ' + ipaddr
            self.send_command(cmd)
            self.pexpect.expect('Conflict:', timeout=8)

    def scan(self):
        if self.Api:
            return str(self.Api.otNodeScan(self.otNode)).split("\n");
        else:
            self.send_command('scan')

            results = []
            while True:
                i = self.pexpect.expect(['\|\s(\S+)\s+\|\s(\S+)\s+\|\s([0-9a-fA-F]{4})\s\|\s([0-9a-fA-F]{16})\s\|\s(\d+)\r\n',
                                         'Done'])
                if i == 0:
                    results.append(self.pexpect.match.groups())
                else:
                    break

            return results

    def ping(self, ipaddr, num_responses=1, size=None):
        if self.Api:
            if size == None:
                size = 100;
            responders = str(self.Api.otNodePing(self.otNode, ipaddr.encode('utf-8'), ctypes.c_uint(size))).split("\n");
            if len(responders) < num_responses:
                raise OSError("Not enough responders to ping!");
            return responders;
        else:
            cmd = 'ping ' + ipaddr
            if size != None:
                cmd += ' ' + str(size)

            self.send_command(cmd)
            responders = {}
            while len(responders) < num_responses:
                i = self.pexpect.expect(['from (\S+):'])
                if i == 0:
                    responders[self.pexpect.match.groups()[0]] = 1
            self.pexpect.expect('\n')
            return responders

    def __init_win_sim(self, nodeid):
        """ Initialize an Windows simulation node. """

        # Load the DLL
        self.Api = ctypes.WinDLL("otnodeapi.dll");
        if self.Api == None:
            raise OSError("Failed to load otnodeapi.dll!");
        
        # Define the functions
        self.Api.otNodeInit.argtypes = [ctypes.c_uint];
        self.Api.otNodeInit.restype = ctypes.c_void_p;

        self.Api.otNodeFinalize.argtypes = [ctypes.c_void_p];

        self.Api.otNodeSetMode.argtypes = [ctypes.c_void_p, 
                                           ctypes.c_char_p];

        self.Api.otNodeStart.argtypes = [ctypes.c_void_p];

        self.Api.otNodeStop.argtypes = [ctypes.c_void_p];

        self.Api.otNodeClearWhitelist.argtypes = [ctypes.c_void_p];

        self.Api.otNodeEnableWhitelist.argtypes = [ctypes.c_void_p];

        self.Api.otNodeDisableWhitelist.argtypes = [ctypes.c_void_p];

        self.Api.otNodeAddWhitelist.argtypes = [ctypes.c_void_p, 
                                                ctypes.c_char_p, 
                                                ctypes.c_byte];

        self.Api.otNodeRemoveWhitelist.argtypes = [ctypes.c_void_p, 
                                                   ctypes.c_char_p];
        
        self.Api.otNodeGetAddr16.argtypes = [ctypes.c_void_p];
        self.Api.otNodeGetAddr16.restype = ctypes.c_char_p;
        
        self.Api.otNodeGetAddr64.argtypes = [ctypes.c_void_p];
        self.Api.otNodeGetAddr64.restype = ctypes.c_char_p;

        self.Api.otNodeSetChannel.argtypes = [ctypes.c_void_p, 
                                              ctypes.c_ubyte];
        
        self.Api.otNodeGetKeySequence.argtypes = [ctypes.c_void_p];
        self.Api.otNodeGetKeySequence.restype = ctypes.c_uint;

        self.Api.otNodeSetNetworkIdTimeout.argtypes = [ctypes.c_void_p, 
                                                       ctypes.c_ubyte];

        self.Api.otNodeSetNetworkName.argtypes = [ctypes.c_void_p, 
                                                  ctypes.c_char_p];
        
        self.Api.otNodeGetPanId.argtypes = [ctypes.c_void_p];
        self.Api.otNodeGetPanId.restype = ctypes.c_ushort;

        self.Api.otNodeSetPanId.argtypes = [ctypes.c_void_p, 
                                            ctypes.c_ushort];

        self.Api.otNodeSetRouterUpgradeThreshold.argtypes = [ctypes.c_void_p, 
                                                             ctypes.c_ubyte];

        self.Api.otNodeReleaseRouterId.argtypes = [ctypes.c_void_p, 
                                                   ctypes.c_ubyte];
        
        self.Api.otNodeGetState.argtypes = [ctypes.c_void_p];
        self.Api.otNodeGetState.restype = ctypes.c_char_p;

        self.Api.otNodeSetState.argtypes = [ctypes.c_void_p, 
                                            ctypes.c_char_p];
        
        self.Api.otNodeGetTimeout.argtypes = [ctypes.c_void_p];
        self.Api.otNodeGetTimeout.restype = ctypes.c_uint;

        self.Api.otNodeSetTimeout.argtypes = [ctypes.c_void_p, 
                                            ctypes.c_uint];
        
        self.Api.otNodeGetWeight.argtypes = [ctypes.c_void_p];
        self.Api.otNodeGetWeight.restype = ctypes.c_ubyte;

        self.Api.otNodeSetWeight.argtypes = [ctypes.c_void_p, 
                                             ctypes.c_ubyte];

        self.Api.otNodeAddIpAddr.argtypes = [ctypes.c_void_p, 
                                             ctypes.c_char_p];
        
        self.Api.otNodeGetAddrs.argtypes = [ctypes.c_void_p];
        self.Api.otNodeGetAddrs.restype = ctypes.c_char_p;
        
        self.Api.otNodeGetContextReuseDelay.argtypes = [ctypes.c_void_p];
        self.Api.otNodeGetContextReuseDelay.restype = ctypes.c_uint;

        self.Api.otNodeSetContextReuseDelay.argtypes = [ctypes.c_void_p, 
                                                        ctypes.c_uint];

        self.Api.otNodeAddPrefix.argtypes = [ctypes.c_void_p, 
                                             ctypes.c_char_p, 
                                             ctypes.c_char_p, 
                                             ctypes.c_char_p];

        self.Api.otNodeRemovePrefix.argtypes = [ctypes.c_void_p, 
                                                ctypes.c_char_p];

        self.Api.otNodeAddRoute.argtypes = [ctypes.c_void_p, 
                                            ctypes.c_char_p, 
                                            ctypes.c_char_p];

        self.Api.otNodeRemoveRoute.argtypes = [ctypes.c_void_p, 
                                               ctypes.c_char_p];

        self.Api.otNodeRegisterNetdata.argtypes = [ctypes.c_void_p];

        self.Api.otNodeEnergyScan.argtypes = [ctypes.c_void_p, 
                                              ctypes.c_uint, 
                                              ctypes.c_ubyte, 
                                              ctypes.c_ushort, 
                                              ctypes.c_ushort, 
                                              ctypes.c_char_p];

        self.Api.otNodePanIdQuery.argtypes = [ctypes.c_void_p, 
                                              ctypes.c_ushort, 
                                              ctypes.c_uint, 
                                              ctypes.c_char_p];

        self.Api.otNodeScan.argtypes = [ctypes.c_void_p];
        self.Api.otNodeScan.restype = ctypes.c_char_p;

        self.Api.otNodePing.argtypes = [ctypes.c_void_p, 
                                        ctypes.c_char_p, 
                                        ctypes.c_uint, 
                                        ctypes.c_uint];
        self.Api.otNodePing.restype = ctypes.c_char_p;


        # Initialize a new node
        self.otNode = self.Api.otNodeInit(ctypes.c_uint(nodeid));
        if self.otNode == None:
            raise OSError("otNodeInit failed!");

if __name__ == '__main__':
    unittest.main()
