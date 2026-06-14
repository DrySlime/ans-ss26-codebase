"""
Copyright (c) 2025 Computer Networks Group @ UPB

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""


# Class for an edge in the graph
class Edge:
    def __init__(self):
        self.lnode = None
        self.rnode = None

    def remove(self):
        self.lnode.edges.remove(self)
        self.rnode.edges.remove(self)
        self.lnode = None
        self.rnode = None


# Class for a node in the graph
class Node:
    def __init__(self, id, type):
        self.edges = []
        self.id = id
        self.type = type

    # Add an edge connected to another node
    def add_edge(self, node):
        edge = Edge()
        edge.lnode = self
        edge.rnode = node
        self.edges.append(edge)
        node.edges.append(edge)
        return edge

    # Remove an edge from the node
    def remove_edge(self, edge):
        self.edges.remove(edge)

    # Decide if another node is a neighbor
    def is_neighbor(self, node):
        for edge in self.edges:
            if edge.lnode == node or edge.rnode == node:
                return True
        return False


class Fattree:

    def __init__(self, num_ports):
        self.servers = []
        self.switches = []
        self.generate(num_ports)

    def generate(self, num_ports):
        if num_ports < 2 or num_ports % 2:
            raise ValueError("num_ports must be a positive even number")

        agg_and_edge_switch_per_pod = num_ports // 2
        ports_to_core_switches = num_ports // 2

        core_switches = []
        agg_switches = []
        edge_switches = []

        # generate core switches
        for agg in range(1, agg_and_edge_switch_per_pod + 1):
            for port in range(1, ports_to_core_switches + 1):
                core_switches.append(Node(f"core_{num_ports}_{agg}_{port}", "core"))

        # generate edge and aggregation switches
        for pod in range(num_ports):
            for agg_sw in range(agg_and_edge_switch_per_pod, num_ports):
                agg_switches.append(Node(f"pod_{pod}_agg_{agg_sw}", "aggregation"))

            for edge_sw in range(agg_and_edge_switch_per_pod):
                edge_switches.append(Node(f"pod_{pod}_edge_{edge_sw}", "edge"))

                # generate servers
                for server in range(2, agg_and_edge_switch_per_pod + 2):
                    self.servers.append(
                        Node(f"pod_{pod}_edge_{edge_sw}_server_{server}", "server")
                    )

        # create links
        for edge_sw in edge_switches:
            edge_prefix = edge_sw.id.split("_")
            pod = edge_prefix[1]
            edge = edge_prefix[3]
            # edge -> server
            for server in [
                server
                for server in self.servers
                if str(server.id).startswith(f"pod_{pod}_edge_{edge}_")
            ]:
                edge_sw.add_edge(server)
            # aggregation -> edge
            for agg_sw in [
                agg_switch
                for agg_switch in agg_switches
                if str(agg_switch.id).startswith(f"pod_{pod}_")
            ]:
                agg_sw.add_edge(edge_sw)
        # core -> aggregation
        for core_sw in core_switches:
            agg_sw_pos = int(core_sw.id.split("_")[2])
            for agg_sw in [
                agg_switch
                for agg_switch in agg_switches
                if str(agg_switch.id).endswith(
                    f"{agg_and_edge_switch_per_pod + agg_sw_pos - 1}"
                )
            ]:
                core_sw.add_edge(agg_sw)

        self.switches.extend(core_switches)
        self.switches.extend(agg_switches)
        self.switches.extend(edge_switches)
