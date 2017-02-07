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
import unittest
import random
from enum import Enum
from NodeGraph import Graph

import node
# import config

LEADER = 0
NUM_OF_STEPS = 30
START_N_OF_NODES = 20
RAND_SEED = 981203748
# TODO: seems like after exactly 16 routers next node becomes a child
MAXIMUM_ROUTERS = 63  # we cannot create more than 63 routers
MAXIMUM_NODES = 512
START_SLEEP_TIME = 7
RTR_SEL_JITTER = 1


class Mode:
    ROUTER = 'rsdn'
    SED = 'sn'


class State:
    ROUTER = 'router'
    LEADER = 'leader'
    CHILD = 'child'
    DETACHED = 'detached'
    DISABLED = 'disabled'


class Action(Enum):
    START_NODE = 0
    STOP_NODE = 1
    ADD_NODE = 2
    PINGING = 3


class StressTestRandom(unittest.TestCase):
    def add_new_node(self, node_id, mode=None):
        print("Adding new node #", node_id)
        try:
            cur_node = node.Node(node_id)
        except OSError as e:
            # Adapter is restarting sometimes when trying to init new node
            # Exception is ignored and another attempt will be made
            print(e)
            return False
        cur_node.set_panid(0xface)

        if mode is None:
            mode = Mode.ROUTER if node_id == LEADER or random.randrange(2) == 1 else Mode.SED
        # mode = Mode.ROUTER  # TODO: Only routers are supported as for now
        print("Setting mode=", mode)
        self.modes[node_id] = mode
        cur_node.set_mode(mode)
        if mode == Mode.SED:
            cur_node.set_timeout(3)

        if node_id != LEADER:
            cur_node.set_router_selection_jitter(RTR_SEL_JITTER)

        self.nodes[node_id] = cur_node
        self.stopped_ns.add(node_id)
        return True

    def add_new_node_pers(self, node_id, mode=None):
        while not self.add_new_node(node_id, mode):
            pass

    def start_node(self, node_id, sleep_time=START_SLEEP_TIME, leader=False):
        print("Starting node #", node_id)
        self.nodes[node_id].start()
        time.sleep(sleep_time)
        if leader:
            self.nodes[node_id].set_state(State.LEADER)
        # self.nodes[node_id].set_state(State.ROUTER)
        # TODO: as for now for some reason there's limited number of routers (seems to be)
        # if self.nodes[node_id].get_state() != State.LEADER:
        #     self.assertEqual(self.nodes[node_id].get_state(),
        #                      State.ROUTER if self.modes[node_id] == Mode.ROUTER else State.CHILD)
        # while self.nodes[node_id].get_state() in [State.DETACHED, State.DISABLED]:
        #     self.nodes[node_id].scan()
        #     print("C'mon, start up!")
        #     pass
        self.running_ns.add(node_id)
        self.stopped_ns.remove(node_id)

    def stop_node(self, node_id):
        print("Stopping node #", node_id)
        self.nodes[node_id].stop()
        self.running_ns.remove(node_id)
        self.stopped_ns.add(node_id)

    def setUp(self):
        random.seed(RAND_SEED)

        self.nodes = {}
        self.modes = {}
        self.running_ns = set()
        self.stopped_ns = set()
        for i in range(START_N_OF_NODES):
            self.add_new_node_pers(i)

        # self.sniffer = config.create_default_thread_sniffer(SNIFFER)
        # self.sniffer.start()

    def tearDown(self):
        # self.sniffer.stop()
        # del self.sniffer

        for node in list(self.nodes.values()):
            node.stop()
        del self.nodes

    def test(self):
        # just let the network choose a leader
        # self.start_node(LEADER, 0, leader=True)

        for i in range(START_N_OF_NODES):
            self.start_node(i)

        # for i in range(START_N_OF_NODES):
        #     print("Node #%d's [%s] Neighbors" % (i, self.nodes[i].get_addr64()))
        #     print(self.nodes[0].get_neighbors_info())
        #
        # return()

        n_of_nodes = START_N_OF_NODES
        for step in range(NUM_OF_STEPS):
            rand_action = random.choice(list(Action))
            print("Iteration #%d [%s]" % (step, rand_action))
            if rand_action == Action.STOP_NODE:  # stop some node
                if len(self.running_ns) > 0:
                    target = random.sample(self.running_ns, 1)[0]
                    self.stop_node(target)
            elif rand_action == Action.START_NODE:  # start some node
                if len(self.stopped_ns) > 0:
                    target = random.sample(self.stopped_ns, 1)[0]
                    self.start_node(target)
            elif rand_action == Action.ADD_NODE:  # add new node
                if n_of_nodes < MAXIMUM_NODES:
                    self.add_new_node_pers(n_of_nodes)
                    self.start_node(n_of_nodes)
                    n_of_nodes += 1
            elif rand_action == Action.PINGING:
                print("Nodes pinging one another")
                print("Running devices:", self.running_ns)

                # continue
                time.sleep(15)
                # running nodes must participate in the network
                # for node_id in self.running_ns:
                #     # self.nodes[node_id].get_addrs()
                #     # TODO: child remains detached for some time
                #     self.assertNotEqual(self.nodes[node_id].get_state(), State.DISABLED)
                #     self.assertNotEqual(self.nodes[node_id].get_state(), State.DETACHED)

                g = Graph(self.nodes)
                print(g)
                # continue
                for node_id in self.running_ns:
                    for other_n in self.running_ns:
                        if other_n != node_id and g.connected_id(node_id, other_n) and \
                                        self.nodes[node_id].get_partition_id() == \
                                        self.nodes[other_n].get_partition_id():

                            if self.nodes[node_id].get_state() == State.LEADER and \
                                        self.nodes[other_n].get_state() == State.LEADER:
                                print("Two leaders!!! Weird, huh?")
                                continue

                            for addr in self.nodes[other_n].get_addrs():
                                if addr[:4] != 'fe80':
                                    print("Node %s %d [%d] pinging %s %d [%d] on %s"
                                          % (self.nodes[node_id].get_state(), node_id,
                                             self.nodes[node_id].get_partition_id(),
                                             self.nodes[other_n].get_state(), other_n,
                                             self.nodes[other_n].get_partition_id(), addr))
                                    # while not self.nodes[node_id].ping(addr):
                                    #     print("............... Why isn't he picking up?? T_T")
                                    #     pass
                                    self.assertTrue(self.nodes[node_id].ping(addr))

                #     # TODO: need to know who's in node's realm
                #     # # Ping realm-local all-nodes
                #     # self.assertTrue(self.nodes[node_id].ping(
                #     #     'ff03::1', num_responses=len(self.running_ns)-1, size=256))
                #     # # Ping realm-local all-routers
                #     # self.assertTrue(self.nodes[node_id].ping(
                #     #     'ff03::2', num_responses=len(self.running_ns) - 1, size=256))
                # TODO: doesn't seem to be working
                #     self.assertTrue(self.nodes[node_id].ping(
                #         'ff33:0040:fdde:ad00:beef:0:0:1', num_responses=len(self.running_ns)-1, size=256))
            else:
                print("Unsupported action ", rand_action)

        for cur_node in list(self.nodes.values()):
            cur_node.get_state()
            cur_node.get_addrs()

if __name__ == "__main__":
    unittest.main()
