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
        debug = False
        # 1. Server (Hosts) hinzufügen und IP-Zuweisung berechnen
        for server in ft_topo.servers:
            # Format der ft_topo-ID: pod_{pod}_edge_{edge_idx}_server_{server_idx}
            parts = server.id.split("_")
            pod = int(parts[1])
            edge_idx = int(parts[3])
            server_idx = int(parts[5])

            # IP-Berechnung nach Al-Fares-Paper[cite: 204]: ID im Intervall [2, k/2 + 1]
            host_id_byte = server_idx + 2
            ip_address = f"10.{pod}.{edge_idx}.{host_id_byte}"
            # Das korrekte Gateway ist die IP des Edge-Switches (.1) im selben Subnetz
            gateway_ip = f"10.{pod}.{edge_idx}.1"

            if debug:
                print(f"Adding host {server.id} with IP {ip_address}, Gateway {gateway_ip}")

            # MAC-Adresse passend zur Hierarchie generieren
            mac_address = f"00:00:10:{pod:02x}:{edge_idx:02x}:{host_id_byte:02x}"

            # Alphanumerischer Name für Mininet (z.B. pod0edge1server0 für pod 0, edge 1, server 0)
            clean_host_name = f"p{pod}e{edge_idx}s{server_idx}"

            self.addHost(
                clean_host_name, 
                ip=f"{ip_address}/24", 
                mac=mac_address,
                defaultRoute=f"via {gateway_ip}"
            )

        # 2. Switches mit bereinigten Namen hinzufügen
        node_name_map = {}
        k = ft_topo.numports
        n = k // 2

        for switch in ft_topo.switches:
            parts = switch.id.split("_")
            
            if switch.type == "core":
                core_idx = int(parts[1])
                # Koordinaten j und i für 10.k.j.i
                i = (core_idx // n) + 1
                j = (core_idx % n) + 1
                ip_address = f"10.{k}.{j}.{i}"
                
                clean_name = f"c{core_idx}"
                dpid_hex = f"00000000000100{core_idx:02x}"
                
            elif switch.type == "aggregation":
                pod = int(parts[1])
                agg_idx = int(parts[3])
                # Offset n für Aggregation-Switches
                switch_id = agg_idx + n
                ip_address = f"10.{pod}.{switch_id}.1"
                
                clean_name = f"p{pod}a{agg_idx}"
                dpid_hex = f"000000000002{pod:02x}{agg_idx:02x}"
                
            elif switch.type == "edge":
                pod = int(parts[1])
                edge_idx = int(parts[3])
                # Direkter Index für Edge-Switches
                switch_id = edge_idx
                ip_address = f"10.{pod}.{switch_id}.1"
                
                clean_name = f"p{pod}e{edge_idx}"
                dpid_hex = f"000000000003{pod:02x}{edge_idx:02x}"

            node_name_map[switch.id] = clean_name
            
            # Switch mit dpid und logischer IP hinzufügen
            if debug:
                print(f"Adding switch {clean_name} with IP {ip_address}")
            self.addSwitch(clean_name, dpid=dpid_hex, ip=ip_address)
            
        # 3. Kanten (Links) hinzufügen
        added_links = set()
        
        link_opts = dict(
            bw=15,       # 15 Mbps Bandbreite
            delay='5ms', # 5 ms Latenz
            use_tclink=True
        )

        for switch in ft_topo.switches:
            s_clean = node_name_map[switch.id]
            
            for edge in switch.edges:
                n1_id = edge.lnode.id
                n2_id = edge.rnode.id
                
                link_id = frozenset([n1_id, n2_id])
                
                if link_id not in added_links:
                    # Prüfen, ob der Zielknoten ein Server (Host) ist
                    if "server" in n1_id or "server" in n2_id:
                        srv_id = n1_id if "server" in n1_id else n2_id
                        parts = srv_id.split("_")
                        target_clean = f"p{parts[1]}e{parts[3]}s{parts[5]}"
                    else:
                        # Zielknoten ist ein Switch -> Mapping nutzen
                        target_id = n1_id if n1_id != switch.id else n2_id
                        target_clean = node_name_map[target_id]

                    self.addLink(s_clean, target_clean, **link_opts)
                    added_links.add(link_id)



def make_mininet_instance(graph_topo):

    net_topo = FattreeNet(graph_topo)
    net = Mininet(topo=net_topo, controller=None, autoSetMacs=True, link=TCLink)
    net.addController('ctrl0', controller=RemoteController,
                      ip="127.0.0.1", port=6653)
    return net


def run(graph_topo):

    # Run the Mininet CLI with a given topology
    lg.setLogLevel('info')
    # mininet.clean.cleanup()
    net = make_mininet_instance(graph_topo)

    info('*** Starting network ***\n')
    net.start()
    info('*** Running CLI ***\n')
    CLI(net)
    info('*** Stopping network ***\n')
    net.stop()
    mininet.clean.cleanup()


if __name__ == '__main__':
    ft_topo = topo.Fattree(4)
    run(ft_topo)
