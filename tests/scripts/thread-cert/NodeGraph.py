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

import networkx as nx
import matplotlib.pyplot as plt
from copy import deepcopy


class Graph:
    def __init__(self, nodes):
        self.addr_ids = {}
        self.node_ids = {}
        self.n_nodes = len(nodes)
        for node_id in range(self.n_nodes):
            addr = nodes[node_id].get_addr64()
            self.addr_ids[addr] = node_id
            self.node_ids[nodes[node_id]] = node_id

        self.matrix = [[False] * self.n_nodes for _ in range(self.n_nodes)]

        # Preset matrix for directly connected
        for i in range(self.n_nodes):
            self.matrix[i][i] = True
            neighbors = nodes[i].get_neighbors_info()
            print(i, "neighbors", neighbors)
            for addr in neighbors:
                self.matrix[i][self.addr_ids[addr]] = True

        self.adj = deepcopy(self.matrix)

        # We require two-way connectivity
        for i in range(self.n_nodes):
            for j in range(self.n_nodes):
                self.matrix[i][j] = self.matrix[i][j] and self.matrix[j][i]

        # Calculate connectivity matrix using Floyd-Warshall algorithm
        for k in range(self.n_nodes):
            for i in range(self.n_nodes):
                for j in range(self.n_nodes):
                    self.matrix[i][j] = self.matrix[i][j] or \
                                        (self.matrix[i][k] and self.matrix[k][j])

    def connected(self, node_a, node_b):
        return self.matrix[self.node_ids[node_a]][self.node_ids[node_b]]

    def connected_id(self, node_a_id, node_b_id):
        return self.matrix[node_a_id][node_b_id]

    def __str__(self):
        res = "Reachability Graph:\n"
        res += str(self.addr_ids)
        for row in self.matrix:
            res += "\n" + str(row)
        return res

    def draw(self, states, parts, fig_id=None, show=False, directed=True):
        g = nx.DiGraph() if directed else nx.Graph()
        for addr in self.addr_ids:
            g.add_node(self.addr_ids[addr], address=addr)
        for i in range(self.n_nodes):
            for j in range(self.n_nodes):
                if i != j and self.adj[i][j] and (directed or self.adj[j][i]):
                    g.add_edge(i, j)
        colours = ['rbgc'[states[i]] for i in range(self.n_nodes)]
        labels = dict((n, "%d [%d]: %s" % (n, parts[n], d['address'])) for (n, d) in g.nodes(data=True))
        plt.clf()
        plt.ioff()
        plt.figure(figsize=(20, 20))
        pos = nx.spring_layout(g, k=1.5, iterations=20)
        nx.draw(g, pos, labels=labels, node_color=colours, edge_color='m')
        plt.savefig("..\\Results\\cout\\figure_" + str(fig_id) + ".png", dpi=1000)
        if show:
            plt.show(block=False)
