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

import random

import mininet
import mininet.clean
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.link import TCLink
from mininet.node import Node, OVSKernelSwitch, RemoteController
from mininet.topo import Topo
from mininet.util import waitListening, custom
import json

import topo


class FattreeNet(Topo):
    """
    Create a fat-tree network in Mininet 
    """

    def __init__(self, ft_topo):
        Topo.__init__(self)
        debug = True
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


def run_parallel_iperf(net, host_pairs, duration=10):
    servers = []
    client_procs = []
    
    # 1. Brutaler Cleanup: Alte iperf-Leichen killen
    for host in net.hosts:
        host.cmd('killall -9 iperf')
    
    info("*** Starte iperf Server im Hintergrund\n")
    for _, server_name in host_pairs:
        server = net.get(server_name)
        # BESSER: Nutzen von popen für stabile Hintergrundprozesse
        p_server = server.popen('iperf -s')
        servers.append(p_server)

    # Längere Pause, damit alle Server wirklich auf Port 5001 lauschen
    time.sleep(3)

    info(f"*** Starte parallele iperf Clients ({duration}s)\n")
    for client_name, server_name in host_pairs:
        client = net.get(client_name)
        server = net.get(server_name)
        # Asynchroner Aufruf
        p_client = client.popen(f'iperf -c {server.IP()} -t {duration}')
        client_procs.append((client.name, p_client))
        
        # WICHTIG: Winzige Pause, um TCP-Handshake-Stürme und CPU-Lockups zu verhindern
        time.sleep(0.2)

    aggregate_throughput = 0.0

    # Ergebnisse einsammeln und parsen
    for name, p in client_procs:
        stdout, _ = p.communicate()
        output = stdout.decode('utf-8')
        
        # Zum Debuggen aktiv lassen, bis wir sicher sind, dass alle Flows klappen:
        print(f"Output von {name}:\n{output}")
        
        lines = output.strip().split('\n')
        if lines:
            last_line = lines[-1]
            if "bits/sec" in last_line:
                parts = last_line.split()
                try:
                    val = float(parts[-2])
                    unit = parts[-1]
                    if unit.startswith('G'): val *= 1000
                    elif unit.startswith('K'): val /= 1000
                    
                    aggregate_throughput += val
                    info(f"  {name}: {val:.2f} Mbps\n")
                except (ValueError, IndexError):
                    info(f"  {name}: Fehler beim Parsen der Ausgabe\n")
            else:
                info(f"  {name}: Verbindung fehlgeschlagen (Kein Durchsatz gemessen)\n")

    info(f"*** Aggregierter Gesamtdurchsatz: {aggregate_throughput:.2f} Mbps\n\n")

    # Cleanup Server
    for p_server in servers:
        p_server.terminate()
    for host in net.hosts:
        host.cmd('killall -9 iperf')
        
    return aggregate_throughput



def generate_stride_pairs(net, stride=1):
    """
    Stride(i) Pattern: Host x sendet an Host (x + stride) mod 16.
    Garantiert gleichmäßige Auslastung aller Bisection-Pfade.
    """
    hosts = sorted([h.name for h in net.hosts])
    pairs = []
    num_hosts = len(hosts)
    for i in range(num_hosts):
        sender = hosts[i]
        receiver = hosts[(i + stride) % num_hosts]
        pairs.append((sender, receiver))
    return pairs

def generate_random_pairs(net):
    """
    Random Pattern: 1-to-1 Mapping aller Hosts.
    Prüft die durchschnittliche Effizienz der statischen Hash-Verteilung.
    """
    hosts = sorted([h.name for h in net.hosts])
    receivers = list(hosts)
    random.shuffle(receivers)
    
    pairs = []
    for sender, receiver in zip(hosts, receivers):
        if sender != receiver:
            pairs.append((sender, receiver))
    return pairs


def run(graph_topo):
    lg.setLogLevel('info')
    net = make_mininet_instance(graph_topo)

    info('*** Starting network ***\n')
    net.start()
    
    # Konvergenzzeit für Controller-Topologie-Discovery und Flow-Rules
    time.sleep(10)
    
    info('*** Fülle ARP-Tabellen via PingAll (Vermeidet ARP-Broadcast-Stürme während iperf) ***\n')
    net.pingAll()
    
    results = {}

    # -------------------------------------------------------------------------
    # TEST 1: Intra-Edge Traffic (L2-Switching Baseline)
    # -------------------------------------------------------------------------
    # Setup:     Kommunikation zwischen Hosts am selben Edge-Switch (gleiches /24 Subnetz).
    # Metrik:    L2-Switching-Kapazität der Leaf-Nodes.
    # Erwartung: Traffic erreicht nicht den Aggregation-Layer. Beide Routing-Schemata 
    #            müssen den vollen, ungedrosselten aggregierten Durchsatz erreichen.
    # -------------------------------------------------------------------------
    info('\n=== Starte Test 1: Intra-Edge Traffic ===\n')
    test1_pairs = [
        ('p0e0s0', 'p0e0s1'),  # Pod 0, Edge 0
        ('p1e1s0', 'p1e1s1'),  # Pod 1, Edge 1
        ('p2e0s0', 'p2e0s1'),  # Pod 2, Edge 0
        ('p3e1s0', 'p3e1s1')   # Pod 3, Edge 1
    ]
    results['test1_intra_edge_mbps'] = run_parallel_iperf(net, test1_pairs, duration=10)


    # -------------------------------------------------------------------------
    # TEST 2: Intra-Pod Traffic (Aggregation Layer)
    # -------------------------------------------------------------------------
    # Setup:     Hosts im selben Pod, aber an unterschiedlichen Edge-Switches.
    # Metrik:    Auslastung der Uplinks zwischen Edge- und Aggregation-Switches.
    # Erwartung: Single-Path kann hier bereits leicht degradieren, wenn die ECMP-
    #            Hash-Funktion (oder der statische Baum) mehrere Ströme auf denselben 
    #            Aggregation-Switch mappt. Multi-Path verteilt ideal.
    # -------------------------------------------------------------------------
    info('\n=== Starte Test 2: Intra-Pod Traffic ===\n')
    test2_pairs = [
        ('p0e0s0', 'p0e1s0'),  # Pod 0: Edge 0 -> Edge 1
        ('p0e0s1', 'p0e1s1'),  # Pod 0: Edge 0 -> Edge 1
        ('p1e0s0', 'p1e1s0'),  # Pod 1: Edge 0 -> Edge 1
        ('p1e0s1', 'p1e1s1')   # Pod 1: Edge 0 -> Edge 1
    ]
    results['test2_intra_pod_mbps'] = run_parallel_iperf(net, test2_pairs, duration=10)


    # -------------------------------------------------------------------------
    # TEST 3: Inter-Pod Single-Flow (Baseline Core)
    # -------------------------------------------------------------------------
    # Setup:     Ein isolierter Datenstrom quer durch die gesamte Topologie.
    # Metrik:    Ermittlung der maximalen Einzelverbindungs-Bandbreite.
    # Erwartung: Da keine Pfadkonkurrenz herrscht, erzielen Single-Path und 
    #            Multi-Path exakt identische Werte (nahe Link-Kapazität).
    # -------------------------------------------------------------------------
    info('\n=== Starte Test 3: Inter-Pod Single-Flow Baseline ===\n')
    test3_pairs = [
        ('p0e0s0', 'p3e1s1')   # Diagonal durch das gesamte RZ
    ]
    results['test3_inter_pod_single_mbps'] = run_parallel_iperf(net, test3_pairs, duration=10)


    # -------------------------------------------------------------------------
    # TEST 4: Inter-Pod Bisection-Traffic (Worst-Case L3-Routing)
    # -------------------------------------------------------------------------
    # Setup:     Maximale Überbuchung (Oversubscription). Die linke RZ-Hälfte (Pod 0,1)
    #            sendet asynchron zur rechten Hälfte (Pod 2,3).
    # Metrik:    Bisection Bandwidth.
    # Erwartung: 
    #   - Single-Path: Kollaps. Alle Flüsse werden durch den Spanning-Tree 
    #     oder OSPF auf denselben Core-Switch (Bottleneck) geroutet.
    #   - Multi-Path: Linear skalierender aggregierter Durchsatz durch 
    #     Ausnutzung aller (k/2)^2 = 4 Core-Switches.
    # -------------------------------------------------------------------------
    info('\n=== Starte Test 4: Inter-Pod Bisection Traffic ===\n')
    test4_pairs = [
        ('p0e0s0', 'p2e0s0'),
        ('p0e0s1', 'p2e0s1'),
        ('p0e1s0', 'p2e1s0'),
        ('p0e1s1', 'p2e1s1'),
        ('p1e0s0', 'p3e0s0'),
        ('p1e0s1', 'p3e0s1'),
        ('p1e1s0', 'p3e1s0'),
        ('p1e1s1', 'p3e1s1')
    ]
    results['test4_inter_pod_bisection_mbps'] = run_parallel_iperf(net, test4_pairs, duration=15)
    # Aufruf in run():
    info('\n=== Starte Test 5: Inter-Pod Stride(1) Traffic ===\n')
    test4_pairs = generate_stride_pairs(net, stride=1)
    results['test5_stride_1_mbps'] = run_parallel_iperf(net, test4_pairs, duration=15)

    info('\n=== Starte Test 6: Inter-Pod Stride(4) Traffic ===\n')
    test5_pairs = generate_stride_pairs(net, stride=4)
    results['test6_stride_4_mbps'] = run_parallel_iperf(net, test5_pairs, duration=15)

    info('\n=== Starte Test 7: Random Traffic ===\n')
    test6_pairs = generate_random_pairs(net)
    results['test7_random_mbps'] = run_parallel_iperf(net, test6_pairs, duration=15)

    info('\n=== Starte Test: Echter Same-ID Worst-Case ===\n') # stand was im Paper zu
    worst_case_pairs = [
        ('p0e0s0', 'p2e0s0'), # 10.0.0.2 sendet an 10.2.0.2 (Host-ID 2)
        ('p0e0s1', 'p3e0s0'), # 10.0.0.3 sendet an 10.3.0.2 (Host-ID 2) -> Kollision an p0a0!
        ('p1e0s0', 'p2e1s0'), # 10.1.0.2 sendet an 10.2.1.2 (Host-ID 2)
        ('p1e0s1', 'p3e1s0')  # 10.1.0.3 sendet an 10.3.1.2 (Host-ID 2) -> Kollision an p1a0!
    ]


    # Ergebnisse als strukturiertes JSON auf der VM ablegen
    output_file = "traffic_results.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)
    info(f"\n*** Detaillierte Ergebnisse in {output_file} exportiert.\n")

    info('*** Stopping network ***\n')
    net.stop()
    mininet.clean.cleanup()


if __name__ == '__main__':
    ft_topo = topo.Fattree(4)
    run(ft_topo)