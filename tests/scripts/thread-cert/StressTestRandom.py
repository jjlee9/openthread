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


import time
from datetime import datetime
import unittest
import random
from enum import Enum
from NodeGraph import Graph

import node

LEADER = 0
NUM_OF_STEPS = 30
START_N_OF_NODES = 30
RAND_SEED = 981203747

MAXIMUM_ROUTERS = 63  # there cannot be more than 63 routers
MAXIMUM_NODES = 512

START_TRIES = 30
START_SLEEP_TIME = 3
CHILD_TIMEOUT = 3
LEADER_REELECT_TL = 60 * 3

RTR_SEL_JITTER = 1
RTR_UPGRADE_THR = MAXIMUM_ROUTERS  # default = 16
RTR_DOWNGRADE_THR = MAXIMUM_ROUTERS  # default = 23


class Mode:
    ROUTER = 'rsdn'
    SED = 'sn'


class State:
    ROUTER = 'router'
    LEADER = 'leader'
    CHILD = 'child'
    DETACHED = 'detached'
    DISABLED = 'disabled'
    OFFLINE = 'offline'
    OFFLINE_STATES = [DISABLED, DETACHED, OFFLINE]
    ROUTER_STATES = [LEADER, ROUTER]
    CHILD_STATES = [CHILD]


class Action(Enum):
    START_NODE = 0
    STOP_NODE = 1
    ADD_NODE = 2
    CHECK = 3


class StressTestRandom(unittest.TestCase):
    def add_new_node(self, node_id, mode=None):
        self.log("Adding new node #", node_id)
        cur_node = node.Node(node_id)
        cur_node.set_panid(0xface)

        if mode is None:
            mode = Mode.ROUTER \
                if (node_id == LEADER or random.randrange(2) == 1) and self.router_cnt < MAXIMUM_ROUTERS \
                else Mode.SED
        mode = Mode.ROUTER
        self.log("Setting mode", mode)
        self.modes[node_id] = mode
        cur_node.set_mode(mode)

        if mode == Mode.SED:
            cur_node.set_timeout(CHILD_TIMEOUT)
        if mode == Mode.ROUTER:
            cur_node.set_router_selection_jitter(RTR_SEL_JITTER)
            cur_node.set_router_upgrade_threshold(RTR_UPGRADE_THR)
            cur_node.set_router_downgrade_threshold(RTR_DOWNGRADE_THR)
            self.router_cnt += 1

        self.nodes[node_id] = cur_node
        self.node_cnt += 1
        self.stopped_ns.add(node_id)

    def await_start(self, node_id, desired_states=None):
        # For some nodes it may take longer to start
        for try_i in range(START_TRIES):
            time.sleep(START_SLEEP_TIME)
            self.states[node_id] = self.nodes[node_id].get_state()
            if (self.states[node_id] not in State.OFFLINE_STATES) and \
                    (desired_states is None or self.states[node_id] in desired_states):
                break

    def start_node(self, node_id):
        self.log("Starting node %d [%s]" % (node_id, self.modes[node_id]))
        self.nodes[node_id].start()
        self.await_start(node_id)
        # self.await_start(node_id, desired_states=(State.ROUTER_STATES
        #                                           if self.modes[node_id] == Mode.ROUTER
        #                                           else State.CHILD_STATES))
        self.assertFalse(self.states[node_id] in State.OFFLINE_STATES)

        # TODO: sometimes router remains a 'child' (after a restart)
        # self.assertTrue(self.states[node_id] in
        #                 (State.ROUTER_STATES if self.modes[node_id] == Mode.ROUTER else State.CHILD_STATES))

        self.running_ns.add(node_id)
        self.stopped_ns.remove(node_id)

    def stop_node(self, node_id):
        self.log("Stopping node", node_id)
        if self.states[node_id] == State.LEADER:
            self.leader_down_t = time.time()
        self.states[node_id] = State.DISABLED
        self.nodes[node_id].stop()
        self.running_ns.remove(node_id)
        self.stopped_ns.add(node_id)

    def setUp(self):
        random.seed(RAND_SEED)

        self.nodes = {}
        self.modes = {}
        self.states = {}
        self.running_ns = set()
        self.stopped_ns = set()
        self.router_cnt = 0
        self.node_cnt = 0
        self.leader_down_t = time.time()
        for i in range(START_N_OF_NODES):
            self.add_new_node(i)

    def tearDown(self):
        for node_i in list(self.nodes.values()):
            node_i.stop()
        del self.nodes

    def setup_graph(self, f_id):
        self.g = Graph(self.nodes)
        self.log(self.g)
        # self.g.draw([0 if self.states[x] == State.LEADER else
        #              (1 if self.states[x] == State.ROUTER else
        #               (2 if self.states[x] in State.CHILD_STATES else 3))
        #              for x in range(self.node_cnt)],
        #             [self.nodes[x].get_partition_id() for x in range(self.node_cnt)],
        #             f_id)

    def log(self, msg, *args):
        print("::", "{0:%d/%m/%y %H:%M:%S.%f}".format(datetime.now())[:-3], msg, *args)

    def test(self):
        for i in range(START_N_OF_NODES):
            self.start_node(i)

        for step in range(NUM_OF_STEPS):
            rand_action = random.choice(list(Action))
            self.log("Iteration #%d [%s]" % (step, rand_action.name))
            if rand_action == Action.STOP_NODE:
                if len(self.running_ns) > 0:
                    target = random.sample(self.running_ns, 1)[0]
                    self.stop_node(target)
            elif rand_action == Action.START_NODE:
                if len(self.stopped_ns) > 0:
                    target = random.sample(self.stopped_ns, 1)[0]
                    self.start_node(target)
            elif rand_action == Action.ADD_NODE:
                if self.node_cnt < MAXIMUM_NODES:
                    self.add_new_node(self.node_cnt)
                    self.start_node(self.node_cnt - 1)  # node_cnt-1 because of increment inside add_new_node
            elif rand_action == Action.CHECK:
                self.log("Running devices:", self.running_ns)

                self.log("Await some reconfigurations of the network to complete...")
                time.sleep(20)

                # running nodes must participate in the network
                num_routers, num_seds = self.check_states()

                self.setup_graph(step)

                self.log("Nodes pinging one another")
                for node_id in self.running_ns:
                    # TODO: multicast ping as for now only works with routers
                    # if self.states[node_id] in State.ROUTER_STATES:
                    #     self.check_broad_ping(node_id, num_routers, num_seds)

                    for other_n in self.running_ns:
                        if other_n != node_id and self.g.connected_id(node_id, other_n):
                            self.check_connectivity(node_id, other_n, step)

            else:
                self.log("Unsupported action ", rand_action)

        for cur_node in list(self.nodes.values()):
            cur_node.get_state()
            cur_node.get_addrs()

    def check_states(self):
        self.log("Checking states of running nodes")
        for node_id in self.running_ns:
            self.states[node_id] = self.nodes[node_id].get_state()

        num_offline = sum(self.states[x] in State.OFFLINE_STATES for x in self.running_ns)
        num_leaders = sum(self.states[x] == State.LEADER for x in self.running_ns)
        num_routers = sum(self.states[x] in State.ROUTER_STATES for x in self.running_ns)
        num_seds = sum(self.modes[x] == Mode.SED for x in self.running_ns)

        # All devices should be online unless there's no router/REED to attach to
        self.assertTrue((num_routers == 0 and num_seds == self.running_ns) or num_offline == 0)

        # Should be no more than one leader. Also shouldn't be none for more that LEADER_REELECT_TL secs
        self.assertTrue(num_leaders == 1 or (time.time() - self.leader_down_t) < LEADER_REELECT_TL)

        return num_routers, num_seds

    def check_connectivity(self, node_fr, node_to, step):
        for addr in self.nodes[node_to].get_addrs():
            if addr[:4] != 'fe80':
                self.log("%s %d [part=%d] pinging %s %d [part=%d] on %s"
                         % (self.states[node_fr], node_fr,
                            self.nodes[node_fr].get_partition_id(),
                            self.states[node_to], node_to,
                            self.nodes[node_to].get_partition_id(), addr))

                # self.tries += 1
                # self.failures += not self.nodes[node_fr].ping(addr)
                if not self.nodes[node_fr].ping(addr):
                    self.log(self.nodes[node_to].get_addr64() in self.nodes[node_fr].get_neighbors_info())
                    self.log(self.nodes[node_fr].get_addr64() in self.nodes[node_to].get_neighbors_info())
                    self.log(hex(self.nodes[node_fr].get_addr16()), "->", hex(self.nodes[node_to].get_addr16()))
                    time.sleep(5)
                    self.log(self.nodes[node_fr].ping(addr))
                # self.assertTrue(self.nodes[node_fr].ping(addr))

    def check_broad_ping(self, node_id, num_routers, num_seds):
        self.log("%s %d performing broad ping" % (self.states[node_id], node_id))
        # Ping realm-local all-nodes
        self.assertTrue(self.nodes[node_id].ping(
            'ff03::1',
            num_responses=len(self.running_ns) - num_seds - (self.modes[node_id] != Mode.SED),
            size=256))
        # Ping realm-local all-routers
        self.assertTrue(self.nodes[node_id].ping(
            'ff03::2',
            num_responses=num_routers - (self.states[node_id] in State.ROUTER_STATES),
            size=256))
        # Ping realm-local special address
        self.assertTrue(self.nodes[node_id].ping(
            'ff33:0040:fdde:ad00:beef:0:0:1',
            num_responses=len(self.running_ns) - 1,
            size=256))


if __name__ == "__main__":
    unittest.main()
