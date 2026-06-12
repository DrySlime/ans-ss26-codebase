#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, ether_types
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.ofproto import ether


import topo

class SPRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)
        self.debug = False

        # dpid -> {neighbor_dpid: out_port}
        self.graph = {}
        # dpid -> set(inter_switch_ports)
        self.inter_switch_ports = {}
        # ip -> (dpid, port)
        self.host_locations = {}
        self.k = 4  # Fattree-Parameter (Anzahl Ports pro Switch) - muss mit der Topologie übereinstimmen
        self.topo_net = topo.Fattree(self.k)
        self.datapaths = {} # dpid -> datapath_obj

        self.switch_info = {} # dpid -> {'type': 'core'|'agg'|'edge', 'pod': x, 'idx': y}
        

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


    def _classify_switch(self, dpid):
        """
        Klassifiziert den Switch-Typ basierend auf der Topologie-Struktur.
        Ich habe das nur mit dpid hinbekommen. Google und KI haben mir wenig geholfen die ips per dpid zu ermitteln.
        """
        sw_type_id = (dpid >> 16) & 0xFF
        pod = (dpid >> 8) & 0xFF
        local_idx = dpid & 0xFF
        n = self.k // 2

        meta = {'type': None, 'ip': None}

        if sw_type_id == 1:
            i = (local_idx // n) + 1
            j = (local_idx % n) + 1
            meta['type'] = 'core'
            meta['ip'] = f"10.{self.k}.{j}.{i}"
            meta['i'] = i
            meta['j'] = j
        elif sw_type_id == 2:
            meta['type'] = 'agg'
            meta['ip'] = f"10.{pod}.{local_idx + n}.1"
            meta['pod'] = pod
            meta['idx'] = local_idx + n
        elif sw_type_id == 3:
            meta['type'] = 'edge'
            meta['ip'] = f"10.{pod}.{local_idx}.1"
            meta['pod'] = pod
            meta['idx'] = local_idx

        self.switch_info[dpid] = meta

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        if self.debug:
            print(f"Switch {self._dpid_to_name(ev.switch.dp.id)} entered: Updating topology")
        self._update_topology()
                
        for sw in get_switch(self, None):
            dpid = sw.dp.id
            
            if dpid not in self.graph:
                self.graph[dpid] = {}
            if dpid not in self.inter_switch_ports:
                self.inter_switch_ports[dpid] = set()
            self.datapaths[sw.dp.id] = sw.dp
            self._classify_switch(dpid)
        self.discover_all_hosts()

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
            if self.debug:
                print("-----------------------------------------------------------")
                print(f"Received ARP PacketIn on {self._dpid_to_name(dpid)}: {src_ip} -> {dst_ip}")
        elif ipv4_pkt:
            src_ip = ipv4_pkt.src
            dst_ip = ipv4_pkt.dst
            if self.debug:
                print("-----------------------------------------------------------")
                print(f"Received IPv4 PacketIn on {self._dpid_to_name(dpid)}: {src_ip} -> {dst_ip}")

        # 1. Host-Location dynamisch erlernen (NUR an Edge-Ports)
        if src_ip:
            # Prüfen, ob der Ingress-Port ein Inter-Switch-Link ist
            is_transit_port = in_port in self.inter_switch_ports.get(dpid, set())
            if not is_transit_port:
                self.host_locations[src_ip] = (dpid, in_port, eth.src)

        # 2. ARP Verarbeitung (Control Plane)
        if arp_pkt:
            sw_meta = self.switch_info.get(dpid)
            
            # FALL A: Der Request gilt der Gateway-IP dieses Edge-Switches
            if sw_meta and sw_meta['type'] == 'edge' and dst_ip == sw_meta['ip']:
                if arp_pkt.opcode == arp.ARP_REQUEST:
                    if self.debug:
                        print(f"[ARP-Gateway] {self._dpid_to_name(dpid)} antwortet auf Request für {dst_ip}")
                    self._send_arp_reply(msg, in_port, eth, arp_pkt, sw_meta)
                elif arp_pkt.opcode == arp.ARP_REPLY:
                    if self.debug:
                        print(f"[ARP-Gateway] {self._dpid_to_name(dpid)} empfängt ARP Reply für {dst_ip} (Host ist erreichbar)")
                        self.host_locations[src_ip] = (dpid, in_port, eth.src)
                return  

            # FALL B: Ziel-Host-Location ist bereits bekannt
            if dst_ip in self.host_locations:
                dst_dpid, dst_port, dst_mac = self.host_locations[dst_ip]
                
                if dpid == dst_dpid:
                    out_port = dst_port
                else:
                    path = self.dijkstra(dpid, dst_dpid)
                    if len(path) < 2:
                        return
                    out_port = self.graph[dpid][path[1]]
                
                actions = [parser.OFPActionOutput(out_port)]
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                          in_port=in_port, actions=actions, data=msg.data)
                datapath.send_msg(out)
            # FALL C: Ziel-Host-Location ist unbekannt -> An das korrekte Edge-Tier-Subnetz fluten
            else:
                if self.debug:
                    print(f"[ARP Target unknown] Flooding ARP Request für {dst_ip} via Edge-Target-Struktur")
                self._send_arp_to_target_edge(msg.data, dst_ip)
            
            return


        # 3. IPv4 Forwarding (Data Plane Installation)
        if ipv4_pkt and dst_ip in self.host_locations:
            dst_dpid, dst_port, dst_mac = self.host_locations[dst_ip]
            
            # MAC Rewrite Actions (L3 Routing)
            rewrite_actions = []
            sw_meta = self.switch_info.get(dpid)
            local_gw_mac = f"00:00:10:{sw_meta['pod']:02x}:{sw_meta['idx']:02x}:01" if sw_meta else ""
            
            # Wenn das Paket an das Gateway adressiert wurde, handelt es sich um L3-Routing
            if eth.dst == local_gw_mac:
                dst_sw_meta = self.switch_info.get(dst_dpid)
                if dst_sw_meta:
                    egress_gw_mac = f"00:00:10:{dst_sw_meta['pod']:02x}:{dst_sw_meta['idx']:02x}:01"
                    rewrite_actions.append(parser.OFPActionSetField(eth_src=egress_gw_mac))
                    rewrite_actions.append(parser.OFPActionSetField(eth_dst=dst_mac))
                    rewrite_actions.append(parser.OFPActionDecNwTtl())

            if dpid == dst_dpid:
                # Lokale Zustellung
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
                flow_actions = rewrite_actions + [parser.OFPActionOutput(dst_port)]
                self.add_flow(datapath, 10, match, flow_actions)
                out_port = dst_port
            else:
                path = self.dijkstra(dpid, dst_dpid)
                if len(path) < 2:
                    return
                
                # 1. Ingress Switch (führt das L3-MAC-Rewriting durch)
                match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
                out_p = self.graph[path[0]][path[1]]
                flow_actions = rewrite_actions + [parser.OFPActionOutput(out_p)]
                self.add_flow(datapath, 10, match, flow_actions)
                
                # 2. Transit Switches (Forwarding rein auf Basis der IP-Adresse)
                for i in range(1, len(path) - 1):
                    curr_node = path[i]
                    next_node = path[i+1]
                    out_p_transit = self.graph[curr_node][next_node]
                    
                    switches = get_switch(self, curr_node)
                    if switches:
                        node_dp = switches[0].dp
                        node_parser = node_dp.ofproto_parser
                        t_match = node_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
                        t_actions = [node_parser.OFPActionOutput(out_p_transit)]
                        self.add_flow(node_dp, 10, t_match, t_actions)

                # 3. Target Switch (Egress Edge - Lokale End-Zustellung)
                switches = get_switch(self, dst_dpid)
                if switches:
                    target_dp = switches[0].dp
                    target_parser = target_dp.ofproto_parser
                    e_match = target_parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=dst_ip)
                    e_actions = [target_parser.OFPActionOutput(dst_port)]
                    self.add_flow(target_dp, 10, e_match, e_actions)

                out_port = self.graph[dpid][path[1]]

            # Ursprüngliches Paket manuell mit den L3-Aktionen injizieren (Verhindert 1. Paket Drop)
            po_actions = rewrite_actions + [parser.OFPActionOutput(out_port)]
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=in_port, actions=po_actions, data=msg.data)
            datapath.send_msg(out)
            return
    


    def _send_arp_reply(self, msg, in_port, eth_pkt, arp_pkt, sw_meta):
        """
        Sendet eine ARP-Response zurück an den anfragenden Host.
        
        :param msg: Das originale OFP packet-in Message-Objekt
        :param in_port: Der Switch-Port, auf dem der Request reinkam
        :param eth_pkt: Das extrahierte ethernet.ethernet Paket-Objekt des Requests
        :param arp_pkt: Das extrahierte arp.arp Paket-Objekt des Requests
        """
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Target-IP des Replies ist die Source-IP des Requests
        target_ip = arp_pkt.src_ip
        # Target-MAC des Replies ist die Source-MAC des Requests
        target_mac = arp_pkt.src_mac
        
        # Source-IP des Replies ist die angefragte IP (die Gateway-IP des Routers)
        src_ip = arp_pkt.dst_ip
        # Generiere oder nutze eine dedizierte Router-MAC-Adresse
        # In der Praxis oft statisch pro Switch oder einheitlich für das Gateway

        src_ip = sw_meta['ip']
        src_mac = f"00:00:10:{sw_meta['pod']:02x}:{sw_meta['idx']:02x}:01"

        # 1. Initialisiere neues Packet-Objekt
        pkt = packet.Packet()

        # 2. Ethernet-Header hinzufügen (Unicast zurück zum Host)
        pkt.add_protocol(ethernet.ethernet(
            ethertype=eth_pkt.ethertype,
            dst=target_mac,
            src=src_mac
        ))

        # 3. ARP-Header hinzufügen (ARP-Reply)
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac=target_mac,
            dst_ip=target_ip
        ))

        # 4. Serialisieren des Pakets in Byte-Array
        pkt.serialize()
        data = pkt.data

        # 5. OpenFlow Packet-Out Action definieren (Ausgabe auf in_port)
        actions = [parser.OFPActionOutput(in_port)]
        
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=data
        )
        if self.debug:
            print(f"Sending ARP Reply from {src_ip} ({src_mac}) to {target_ip} ({target_mac}) on port {in_port}")
        # 6. Paket an den Switch senden
        datapath.send_msg(out)

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
                
                # Entspricht dem Format: sw_type_id = 3 (Edge) im dritten Byte
                # dpid = (3 << 16) | (pod << 8) | edge
                dpid = (3 << 16) | (pod << 8) | edge
                return dpid
        except Exception:
            pass
        return None

    def discover_all_hosts(self):
        """
        Iteriert über alle erkannten Edge-Switches und sendet proaktiv
        ARP-Requests an alle potenziellen Host-IPs im jeweiligen Subnetz.
        """
        if self.debug:
            print("[DISCOVERY] Starte proaktive Host-Erkennung in allen Subnetzen...")

        k_half = self.k // 2

        for dpid, sw_meta in self.switch_info.items():
            if sw_meta['type'] != 'edge':
                continue
            
            # KORREKTUR: Datapath direkt aus lokalem Cache auflösen
            datapath = self.datapaths.get(dpid)
            if not datapath:
                if self.debug:
                    print(f"[DISCOVERY-WARN] Kein Datapath-Objekt für Switch {self._dpid_to_name(dpid)} gefunden (noch nicht bereit).")
                continue

            pod = sw_meta['pod']
            subnet = sw_meta['idx']

            for host_suffix in range(2, k_half + 2):
                target_ip = f"10.{pod}.{subnet}.{host_suffix}"
                
                if self.debug:
                    print(f"[DISCOVERY] {self._dpid_to_name(dpid)} -> ARP Probe für {target_ip}")
                
                self._send_arp_request(datapath, target_ip, sw_meta)
    
    def _get_host_facing_ports(self, datapath):
        """Isoliert die Downlink-Ports zum Edge durch Subtraktion der Fabric-Links."""
        ofproto = datapath.ofproto
        dpid = datapath.id
        
        # 1. Alle bekannten Fabric-Ports (Uplinks/Inter-Switch-Links) aus dem Topology-Speicher
        fabric_ports = self.inter_switch_ports.get(dpid, set())
        
        # 2. Alle physischen Ports direkt aus dem Datapath-Objekt auslesen
        # Filtert interne/virtuelle Ports (wie OFPP_LOCAL) heraus
        all_ports = set(
            p.port_no for p in datapath.ports.values() 
            if p.port_no < ofproto.OFPP_MAX
        )
        
        # 3. Differenzmenge = Reine Host-Ports
        return list(all_ports - fabric_ports)
    
    def _send_arp_request(self, datapath, target_ip, sw_meta):
        """
        Generiert einen ARP-Request vom Switch (Gateway) für eine lokale Ziel-IP
        und sendet diesen gezielt ausschließlich an alle Host-facing Ports.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        # 1. Host-Ports über die bestehende Hilfsmethode ermitteln
        host_ports = self._get_host_facing_ports(datapath)
        
        if not host_ports:
            if self.debug:
                print(f"[ARP-GENERATE-ERROR] {self._dpid_to_name(dpid)}: Keine Host-Ports gefunden!")
            return

        # 2. Protokoll-Header aufbauen (Hierarchische Struktur)
        src_ip = sw_meta['ip']
        src_mac = f"00:00:10:{sw_meta['pod']:02x}:{sw_meta['idx']:02x}:01"
        dst_mac = "ff:ff:ff:ff:ff:ff"

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=ether.ETH_TYPE_ARP,
            dst=dst_mac,
            src=src_mac
        ))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=src_mac,
            src_ip=src_ip,
            dst_mac="00:00:00:00:00:00",
            dst_ip=target_ip
        ))
        pkt.serialize()
        data = pkt.data

        # 3. Multicast-Verhalten via OpenFlow Action-List abbilden
        # Es wird eine Output-Aktion pro Host-Schnittstelle generiert
        actions = [parser.OFPActionOutput(p) for p in host_ports]
        
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER, # Eigenes Paket -> Kein Switch-Buffer
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=data
        )
        
        if self.debug:
            print(f"[ARP-GENERATE] {self._dpid_to_name(dpid)} sendet ARP-Request für {target_ip} an Host-Ports: {host_ports}")
            
        datapath.send_msg(out)