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

#!/usr/bin/env python3

import os
import subprocess
import time

import mininet
import mininet.clean
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.link import TCLink
from mininet.node import Node, OVSKernelSwitch, RemoteController
from mininet.topo import Topo
from mininet.util import waitListening, custom

import topo


class FattreeNet(Topo):
    """
    Create a fat-tree network in Mininet
    """

    def __init__(self, ft_topo):

        Topo.__init__(self)

        node_to_mininet_name_map = {}

        # add switches
        for index, switch in enumerate(ft_topo.switches, start=1):
            id_parts = switch.id.split("_")

            if switch.type == "core":
                num_ports = id_parts[1]
                agg_switch_number = id_parts[2]
                agg_switch_port = id_parts[3]
                mininet_name = f"c{num_ports}a{agg_switch_number}p{agg_switch_port}"
                ip_address = f"10.{num_ports}.{agg_switch_number}.{agg_switch_port}"

            if switch.type == "aggregation":
                pod = id_parts[1]
                agg_id = id_parts[3]
                mininet_name = f"p{pod}a{agg_id}"
                ip_address = f"10.{pod}.{agg_id}.1"

            if switch.type == "edge":
                pod = id_parts[1]
                edge_id = id_parts[3]
                mininet_name = f"p{pod}e{edge_id}"
                ip_address = f"10.{pod}.{edge_id}.1"

            node_to_mininet_name_map[switch.id] = mininet_name
            self.addSwitch(mininet_name, ip=ip_address, dpid=f"{index:016x}")

        # add hosts
        for server in ft_topo.servers:
            id_parts = server.id.split("_")
            pod = id_parts[1]
            edge_id = id_parts[3]
            server_id = id_parts[5]

            mininet_name = f"p{pod}e{edge_id}s{server_id}"
            ip_address = f"10.{pod}.{edge_id}.{server_id}/8"
            self.addHost(mininet_name, ip=ip_address)

        # add links
        added_links = set()
        for switch in ft_topo.switches:
            mininet_switch_name = node_to_mininet_name_map[switch.id]

            for edge in switch.edges:
                link_id = frozenset([edge.lnode.id, edge.rnode.id])

                if link_id not in added_links:
                    if edge.lnode.type == "server" or edge.rnode.type == "server":
                        server_id_parts = (
                            edge.lnode.id.split("_")
                            if edge.lnode.type == "server"
                            else edge.rnode.id.split("_")
                        )
                        mininet_target_name = f"p{server_id_parts[1]}e{server_id_parts[3]}s{server_id_parts[5]}"
                    else:
                        mininet_target_name = (
                            node_to_mininet_name_map[edge.lnode.id]
                            if edge.lnode.id != switch.id
                            else node_to_mininet_name_map[edge.rnode.id]
                        )
                    self.addLink(
                        mininet_switch_name,
                        mininet_target_name,
                        cls=TCLink,
                        bw=15,
                        delay="5ms",
                    )
                    added_links.add(link_id)


def make_mininet_instance(graph_topo):

    net_topo = FattreeNet(graph_topo)
    net = Mininet(topo=net_topo, controller=None, autoSetMacs=True)
    net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
    return net


def run(graph_topo):

    # Run the Mininet CLI with a given topology
    lg.setLogLevel("info")
    # mininet.clean.cleanup()
    net = make_mininet_instance(graph_topo)

    info("*** Starting network ***\n")
    net.start()
    info("*** Running CLI ***\n")
    CLI(net)
    info("*** Stopping network ***\n")
    net.stop()
    mininet.clean.cleanup()


if __name__ == "__main__":
    ft_topo = topo.Fattree(4)
    run(ft_topo)
