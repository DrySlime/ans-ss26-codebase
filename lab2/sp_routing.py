#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, ether_types
from ryu.topology import event
from ryu.topology.api import get_switch, get_link

class SPRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)
        self.debug = True

        # dpid -> {neighbor_dpid: out_port}
        self.graph = {}
        # dpid -> set(inter_switch_ports)
        self.inter_switch_ports = {}
        # ip -> (dpid, port)
        self.host_locations = {}

    def _update_topology(self):
        """Holt Topologie-Daten zur Laufzeit und aktualisiert die Graphen-Struktur."""
        switches = get_switch(self, None)
        links = get_link(self, None)


        for sw in switches:
            dpid = sw.dp.id
            
            if dpid not in self.graph:
                self.graph[dpid] = {}
            if dpid not in self.inter_switch_ports:
                self.inter_switch_ports[dpid] = set()

        for link in links:
            src_dpid = link.src.dpid
            dst_dpid = link.dst.dpid
            src_port = link.src.port_no
            

            # Kante und Inter-Switch-Port registrieren
            if src_dpid in self.graph:

                self.graph[src_dpid][dst_dpid] = src_port
                self.inter_switch_ports[src_dpid].add(src_port)

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        self._update_topology()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-Miss Flow Entry (Prio 0): Alles an den Controller senden
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def dijkstra(self, start, end):
        """Berechnet den kürzesten Pfad mittels Dijkstra-Algorithmus."""
        dist = {n: float('inf') for n in self.graph}
        prev = {n: None for n in self.graph}
        
        if start not in dist or end not in dist:
            return []

        dist[start] = 0
        unvisited = set(self.graph.keys())

        while unvisited:
            curr = min(unvisited, key=lambda n: dist[n])
            if dist[curr] == float('inf') or curr == end:
                break
            
            unvisited.remove(curr)

            for neighbor in self.graph[curr]:
                if neighbor in unvisited:
                    alt = dist[curr] + 1  # Uniforme Kantengewichte (Hop-Count)
                    if alt < dist[neighbor]:
                        dist[neighbor] = alt
                        prev[neighbor] = curr

        # Rekonstruktion des Pfades
        path = []
        curr = end
        if prev[curr] is not None or curr == start:
            while curr is not None:
                path.insert(0, curr)
                curr = prev[curr]
        return path
    
    def _dpid_to_name(self, dpid):
        """
        Dekodiert die Integer-DPID in den human-readable Switch-Namen.
        Erwartet das Format 0xT0P0I (T=Tier, P=Pod, I=Index).
        """
        switch_type = (dpid >> 16) & 0xF
        
        if switch_type == 1:
            core_idx = dpid & 0xFF
            return f"c{core_idx}"
        
        elif switch_type == 2:
            pod = (dpid >> 8) & 0xFF
            agg_idx = dpid & 0xFF
            return f"p{pod}a{agg_idx}"
            
        elif switch_type == 3:
            pod = (dpid >> 8) & 0xFF
            edge_idx = dpid & 0xFF
            return f"p{pod}e{edge_idx}"
            
        return str(dpid)  # Fallback für unbekannte DPIDs

    def _send_arp_to_target_edge(self, data, dst_ip):
        """Sendet ARP-Request als PacketOut exklusiv an den zuständigen Edge-Switch."""
        
        # 1. DPID aus Ziel-IP berechnen (Topologie-spezifisches Mapping)
        target_dpid = self._get_dpid_from_ip(dst_ip)
        # 2. Ziel-Switch auslesen
        switches = get_switch(self, target_dpid)
        if not switches:
            return
            
        sw = switches[0]
        dp = sw.dp
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        
        # 3. Host-Facing-Ports dieses spezifischen Switches isolieren
        all_ports = {p.port_no for p in sw.ports if p.port_no != ofproto.OFPP_LOCAL}
        inter_ports = self.inter_switch_ports.get(target_dpid, set())
        edge_ports = all_ports - inter_ports
        
        # 4. Gezieltes PacketOut NUR an diesen Switch
        if edge_ports:
            actions = [parser.OFPActionOutput(p) for p in edge_ports]
            out = parser.OFPPacketOut(datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
            dp.send_msg(out)

    def _get_dpid_from_ip(self, ip_str):
        try:
            octets = ip_str.split('.')
            if len(octets) == 4 and octets[0] == '10':
                pod = int(octets[1])
                edge = int(octets[2])
                
                # 12 Zeichen Prefix + 2 Pod + 2 Edge = 16 Zeichen -- mininet nimmt nur 16
                dpid_hex = f"000000000003{pod:02x}{edge:02x}"
                return int(dpid_hex, 16)
        except Exception:
            pass
        return None
    

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Sync Topology bei neuem Paket
        self._update_topology()

        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        # Ignoriere LLDP und IPv6 vollständig
        if eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        src_ip = None
        dst_ip = None

        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
        elif ipv4_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst

        # 1. Host-Location dynamisch erlernen (NUR an Edge-Ports)
        if src_ip:
            # Prüfen, ob der Ingress-Port ein Inter-Switch-Link ist
            is_transit_port = in_port in self.inter_switch_ports.get(dpid, set())
            
            if not is_transit_port:
                self.host_locations[src_ip] = (dpid, in_port)

        # 2. ARP Verarbeitung (Control Plane)
        if arp_pkt:
            if dst_ip in self.host_locations:
                # Ziel ist bekannt: Gezieltes Unicast-Forwarding entlang Dijkstra-Pfad
                dst_dpid, dst_port = self.host_locations[dst_ip]
                if dpid == dst_dpid:
                    out_port = dst_port
                    if self.debug:
                        print(f"ARP PacketIn {self._dpid_to_name(dpid)}: {src_ip} -> {dst_ip}, Directly Connected, Out Port: {out_port}")
                else:
                    path = self.dijkstra(dpid, dst_dpid)
                    if self.debug:
                        readable_path = [self._dpid_to_name(node) for node in path]
                        print(f"ARP PacketIn {self._dpid_to_name(dpid)}: {src_ip} -> {dst_ip}, Path: {readable_path}")
                    if len(path) < 2:
                        return
                    out_port = self.graph[dpid][path[1]]
                
                actions = [parser.OFPActionOutput(out_port)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=in_port, actions=actions, data=msg.data)
                datapath.send_msg(out)
            else:
                # Ziel unbekannt: Loop-freier ARP-Flood in das Edge-Tier
                if self.debug:
                    target_dpid = self._get_dpid_from_ip(dst_ip)
                    print(f"ARP PacketIn {self._dpid_to_name(dpid)}: {src_ip} -> {dst_ip}, flooding to edge switch({self._dpid_to_name(target_dpid)})")
                self._send_arp_to_target_edge(msg.data, dst_ip)
            return

        # 3. IPv4 Forwarding (Data Plane Installation)
        if ipv4_pkt and dst_ip in self.host_locations:
            dst_dpid, dst_port = self.host_locations[dst_ip]
            
            if dpid == dst_dpid:
                # Lokale Zustellung
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
                actions = [parser.OFPActionOutput(dst_port)]
                self.add_flow(datapath, 10, match, actions)
                out_port = dst_port
            else:
                path = self.dijkstra(dpid, dst_dpid)
                if len(path) < 2:
                    return
                
                # End-to-End Flow Installation
                for i in range(len(path) - 1):
                    curr_node = path[i]
                    next_node = path[i+1]
                    out_p = self.graph[curr_node][next_node]
                    
                    # Datapath-Objekt des jeweiligen Switches aus der Topologie holen
                    switches = get_switch(self, curr_node)
                    if switches:
                        node_dp = switches[0].dp
                        node_parser = node_dp.ofproto_parser
                        match = node_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
                        actions = [node_parser.OFPActionOutput(out_p)]
                        self.add_flow(node_dp, 10, match, actions)
                        if self.debug:
                            readable_path = [self._dpid_to_name(node) for node in path]
                            print(f"Adding flow on {self._dpid_to_name(curr_node)} for dst {dst_ip}, Path: {readable_path}, Out Port: {out_p}")

                out_port = self.graph[dpid][path[1]]

            # Ursprüngliches Paket in den nun vollständig konfigurierten Pfad injizieren
            actions = [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions,
                                      data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None)
            if self.debug:
                print(f"Forwarding original packet")
            datapath.send_msg(out)
            