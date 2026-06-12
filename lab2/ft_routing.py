#!/usr/bin/env python3

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ipv4, ethernet, arp
from ryu.topology import event
from ryu.topology.api import get_switch, get_link
from ryu.ofproto import ether

import topo

class FTRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FTRouter, self).__init__(*args, **kwargs)
        self.debug = False
        self.k = 4
        self.topo_net = topo.Fattree(self.k)
        self.host_port_table = {} # dpid -> {host_ip: port_no}
        
        # Topologie-Graphen / Adjazenz-Speicher
        self.adjacency = {}   # dpid -> {peer_dpid: port_no}
        self.switch_info = {} # dpid -> {'type': 'core'|'agg'|'edge', 'pod': x, 'idx': y}
        self.pending_messages = {} # dpid -> [(msg, in_port), ...]
        self.datapaths = {} # dpid -> datapath_obj

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        """Registriert neue Switches asynchron (ohne O(N^2) Loop)."""
        sw = ev.switch
        self._classify_switch(sw.dp.id)
        self.datapaths[sw.dp.id] = sw.dp
    
    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        """Aktualisiert die Adjazenzmatrix und triggert Discovery bei Konvergenz."""
        link = ev.link
        src_dpid = link.src.dpid
        dst_dpid = link.dst.dpid
        
        self.adjacency.setdefault(src_dpid, {})[dst_dpid] = link.src.port_no
        self.adjacency.setdefault(dst_dpid, {})[src_dpid] = link.dst.port_no
        
        # Prüfe, ob Edge-Switches nun vollständig in die Fabric integriert sind
        self._check_and_trigger_discovery(src_dpid)
        self._check_and_trigger_discovery(dst_dpid)
    
    def _check_and_trigger_discovery(self, dpid):
        """Triggert ARP-Probes für einen Edge-Switch exakt einmal nach LLDP-Abschluss."""
        sw_meta = self.switch_info.get(dpid)
        if not sw_meta or sw_meta['type'] != 'edge':
            return
            
        fabric_ports = self.adjacency.get(dpid, {})
        # k/2 Uplinks erkannt UND Probes wurden noch nicht gesendet
        if len(fabric_ports) == (self.k // 2) and not sw_meta.get('discovery_done'):
            sw_meta['discovery_done'] = True
            datapath = self.datapaths.get(dpid)
            if datapath:
                if self.debug:
                    print(f"[LLDP OK] {self._dpid_to_name(dpid)} konvergiert. Starte Host-Discovery.")
                self._discover_hosts_on_switch(datapath, sw_meta)
    
    def _discover_hosts_on_switch(self, datapath, sw_meta):
        """Sendet proaktive ARP-Requests ausschließlich für das Subnetz dieses Switches."""
        pod = sw_meta['pod']
        subnet = sw_meta['idx']
        k_half = self.k // 2

        for host_suffix in range(2, k_half + 2):
            target_ip = f"10.{pod}.{subnet}.{host_suffix}"
            self._send_arp_request(datapath, target_ip, sw_meta)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match['in_port']

        # O(1) Lookup des Switch-States
        sw_meta = self.switch_info.get(dpid)
        if not sw_meta:
            return

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        #------------------------------------------------------#
        #  DYNAMIC HOST LEARNING & PROACTIVE PROVISIONING
        #-------------------------------------------------------#
        src_ip = None
        if arp_pkt:
            src_ip = arp_pkt.src_ip
        elif ipv4_pkt:
            src_ip = ipv4_pkt.src
        
        if src_ip and self._is_host_port(dpid, in_port):
            # Read existing state without overwriting
            known_host_data = self.host_port_table.setdefault(dpid, {}).get(src_ip)
            known_port = known_host_data['port'] if known_host_data else None
            
            if known_port != in_port:
                self.host_port_table[dpid][src_ip] = {
                    'port': in_port,
                    'mac': arp_pkt.src_mac if arp_pkt else None
                }
                self._install_host_downward_flow(datapath, src_ip, eth.src, in_port)
                
                if self.debug:
                    print(f"[EDGE-LEARN] {self._dpid_to_name(dpid)}: Host {src_ip} -> Port {in_port} (Flow Prio 100 aktiv)")

        # 1. ARP-Request-Handling
        if arp_pkt and arp_pkt.opcode == arp.ARP_REQUEST:
            ip_octets = arp_pkt.dst_ip.split('.')
            
            # Abbruch, wenn keine gültige Cluster-IP (10.x.x.x)
            if ip_octets[0] != '10': return

            pod = int(ip_octets[1])
            subnet = int(ip_octets[2])
            host_id = int(ip_octets[3])

            # Bestimme, ob das Ziel im selben /24-Subnetz dieses Edge-Switches liegt
            # (Hierzu muss sw_meta die eigene Pod-ID und Aggregation/Edge-ID kennen)
            if sw_meta['type'] == 'edge' and pod == sw_meta['pod'] and subnet == sw_meta['idx']:
                # Fall A: Das Ziel ist im selben Subnetz (.X)
                if host_id == 1:
                    # Host sucht explizit das Gateway (10.pod.edge.1)
                    if self.debug:
                        print(f"Generiere ARP-Response für Gateway {arp_pkt.dst_ip}")
                    self._handle_arp_request(datapath, in_port, eth, arp_pkt)
                else:
                    # Host sucht einen anderen lokalen Host im selben /24-Subnetz -> Fluten/Unicast im Edge-Block
                    if self.debug:
                        print(f"[EDGE-LOCAL] ARP Request für lokalen Host: {arp_pkt.dst_ip}")
                    self._flood_to_hosts(datapath, msg, in_port, arp_pkt.dst_ip)
            else:
                # Fall B: Das Ziel ist in einem ANDEREN Subnetz oder Pod
                # Der Edge-Switch fängt den Request ab und gibt SEINE eigene MAC (bzw. eine virtuelle Gateway-MAC) zurück.
                # Dadurch schickt der Host das IP-Paket an den Edge-Switch, wo es via L3-Regeln hochgeroutet wird.
                if self.debug:
                    print(f"[PROXY-ARP] Abfangen des ARP-Requests für externes Ziel: {arp_pkt.dst_ip} -> Antworte mit Gateway-MAC")
                #self._handle_proxy_arp_request(datapath, in_port, eth, arp_pkt)
                
            return
        
        #2. ARP-Response-Handling
        if arp_pkt and arp_pkt.opcode == arp.ARP_REPLY:
            sw_meta = self.switch_info.get(dpid)
            
            # Prüfen, ob der Reply an die Switch-IP adressiert ist (Antwort auf unseren Probe)
            if sw_meta['type'] == 'edge' and arp_pkt.dst_ip == sw_meta['ip']:
                sender_ip = arp_pkt.src_ip
                
                # State aktualisieren
                self.host_port_table.setdefault(dpid, {})[sender_ip] = {
                    'port': in_port,
                    'mac': arp_pkt.src_mac  # MAC-Adresse aus dem ARP-Header extrahieren
                }
                
                if self.debug:
                    print(f"[EDGE ARP REPLY] ARP Reply von {sender_ip} an Port {in_port} empfangen. Installiere Flow.")

                self._install_host_downward_flow(datapath, sender_ip, arp_pkt.src_mac, in_port)

                #Check buffered messages for this dpid and send them out to the host that just replied to our ARP request
                pending = self.pending_messages.get(dpid, [])
                for pending_msg, pending_in_port in pending:
                    self._reinject_packet_to_table(datapath, pending_msg, pending_in_port)
                    if self.debug:
                        print(f"[PENDING] Re-Inject von gepuffertem Paket (Ingress: {pending_in_port}) für {sender_ip}")
                
                self.pending_messages[dpid] = []
                return
            else:
                if self.debug:
                    print(f"[ARP-FORWARD] Inter-Host Reply: {arp_pkt.src_ip} -> {arp_pkt.dst_ip}")
                
                # Ermittle den Port des Ziel-Hosts (dst_ip) aus der Tabelle
                known_dst_data = self.host_port_table.get(dpid, {}).get(arp_pkt.dst_ip)
                
                if known_dst_data:
                    # Unicast direkt zum Ziel-Port des wartenden Hosts
                    target_port = known_dst_data['port']
                    actions = [parser.OFPActionOutput(target_port)]
                else:
                    # Fallback (Sicherheitsnetz): Subnetz-Flood an alle Host-Ports
                    host_ports = self._get_host_facing_ports(datapath)
                    actions = [parser.OFPActionOutput(p) for p in host_ports if p != in_port]

                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=msg.buffer_id,
                    in_port=in_port,
                    actions=actions,
                    data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                )
                datapath.send_msg(out)
                return
            
        if ipv4_pkt:
            self.install_flow_rules(ev, sw_meta, ipv4_pkt, in_port)
            self._reinject_packet_to_table(datapath, msg, in_port)

        

    # --- Topologie / Port Resolution Helper ---

    
    

    def _classify_switch(self, dpid):
        """
        Klassifiziert den Switch-Typ durch mathematische Umkehrung der DPID.
        Setzt voraus, dass self.k initialisiert ist.
        """
        n = self.k // 2
        core_limit = n * n
        agg_limit = core_limit + (self.k * n)
        edge_limit = agg_limit + (self.k * n)

        meta = {'type': None, 'ip': None}

        if 1 <= dpid <= core_limit:
            # Core Switch
            core_idx = dpid - 1
            i = (core_idx // n) + 1
            j = (core_idx % n) + 1
            meta.update({
                'type': 'core', 
                'ip': f"10.{self.k}.{j}.{i}", 
                'i': i, 
                'j': j
            })
            
        elif core_limit < dpid <= agg_limit:
            # Aggregation Switch
            offset = dpid - core_limit - 1
            pod = offset // n
            local_idx = offset % n
            meta.update({
                'type': 'agg', 
                'ip': f"10.{pod}.{local_idx + n}.1", 
                'pod': pod, 
                'idx': local_idx + n
            })
            
        elif agg_limit < dpid <= edge_limit:
            # Edge Switch
            offset = dpid - agg_limit - 1
            pod = offset // n
            local_idx = offset % n
            meta.update({
                'type': 'edge', 
                'ip': f"10.{pod}.{local_idx}.1", 
                'pod': pod, 
                'idx': local_idx
            })

        self.switch_info[dpid] = meta

    def _get_dynamic_port(self, src_dpid, dst_dpid):
        """Ermittelt den Egress-Port dynamisch aus der Topologie-Adjazenz."""
        return self.adjacency.get(src_dpid, {}).get(dst_dpid, None)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def dynamic_host_learning(self,ev):
        # Learning der Host-Ports auf Edge-Switches durch Beobachtung des Data-Plane Traffics.
        # --- START DYNAMIC HOST LEARNING ---
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        # IP des Senders extrahieren
        src_ip = None
        if arp_pkt:
            src_ip = arp_pkt.src_ip
        elif ipv4_pkt:
            src_ip = ipv4_pkt.src

        # Prüfen, ob in_port ein Inter-Switch-Link ist (O(n) über Values ist hier ok, max. k Ports)
        inter_switch_ports = self.adjacency.get(dpid, {}).values()
        is_host_port = in_port not in inter_switch_ports

        # Source-IP dem Ingress-Port zuordnen, falls von Host empfangen
        sw_meta = self.switch_info.get(dpid)
        if src_ip and sw_meta['type'] == 'edge' and is_host_port:
            self.host_port_table.setdefault(dpid, {})[src_ip] = {
                'port': in_port,
                'mac': arp_pkt.src_mac if arp_pkt else None
            }
            if self.debug:
                print(f"[LEARNING] Switch {self._dpid_to_name(dpid)} lernt Host {src_ip} an Port {in_port}")

            # WICHTIG: Nur für IPv4 (eth_type=0x0800), um ARP-Flussregeln nicht zu korrumpieren
            match_downward = datapath.ofproto_parser.OFPMatch(
                eth_type=0x0800,
                ipv4_dst=src_ip
            )
            
            actions_downward = [datapath.ofproto_parser.OFPActionOutput(in_port)]
            
            # Hohe Priorität (z. B. 100), damit diese exakte Host-Zustellung das 
            # generische Suffix-Routing (Prio 60) oder das Drop-Verhalten (Prio 40) überschreibt.
            self.add_flow(datapath, priority=100, match=match_downward, actions=actions_downward)
        # --- END DYNAMIC HOST LEARNING ---

    def _reinject_packet_to_table(self, datapath, msg, in_port):
        """Sendet ein Paket zurück in die Pipeline des Switches zur erneuten Evaluierung."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        
        # OFPP_TABLE instruiert den Switch, das Paket am Anfang der Flow-Tabellen einzuspeisen
        actions = [parser.OFPActionOutput(ofproto.OFPP_TABLE)]
        
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)

    def install_flow_rules(self, ev, sw_meta, ipv4_pkt, in_port):
        datapath = ev.msg.datapath
        dpid = datapath.id
        dst_ip = ipv4_pkt.dst

        if self.debug:
            print(f"Installiere proaktive Flow Rules auf {self._dpid_to_name(datapath.id)} für Ziel {dst_ip} mit Rolle {sw_meta['type']}")
        
        if sw_meta['type'] == 'core':
            if self.debug:
                print(f"[INSTALL FLOW CORE] switch {self._dpid_to_name(datapath.id)} baut flow rules auf")
            # Core Switches (Algorithmus 2): Longest Prefix Match auf Destination Pod
            # Im paper steht hier [0, k/2 - 1] ist aber falsch uns muss [0, k-1] sein, da die Pods von 0 bis k-1 nummeriert sind.
            # Präfix: 10.x.0.0/16
            for target_pod in range(self.k):
                match = datapath.ofproto_parser.OFPMatch(eth_type=0x0800, ipv4_dst=(f'10.{target_pod}.0.0', '255.255.0.0'))
                priority = 80 # Hohe Prio für /16
                out_port = self._resolve_core_to_pod_port(datapath.id, target_pod)
                if out_port:
                    actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                    self.add_flow(datapath, priority, match, actions)
                else:
                    if self.debug:
                        print(f"[ERROR] Core Switch {self._dpid_to_name(datapath.id)} does not have a port for Pod {target_pod}")

        if sw_meta['type'] == 'agg':
            if self.debug:
                print(f"[INSTALL FLOW AGG] switch {self._dpid_to_name(datapath.id)} baut flow rules auf")

            # Annahme: Pod-ID (x) und Switch-ID (z) innerhalb des Pods sind für den Datapath bekannt.
            # Muss über DPID oder Topologie-Graphen aufgelöst werden.
            pod_x = sw_meta['pod']
            switch_z = sw_meta['idx']
            k_half = self.k // 2

            # 1. Downward Routing (Präfix-Match)
            # Ziel: 10.x.i.0/24 -> Port i (Edge-Switches im gleichen Pod)
            for i in range(k_half):
                match = datapath.ofproto_parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_dst=(f'10.{pod_x}.{i}.0', '255.255.255.0')
                )
                out_port = self._resolve_agg_to_edge_port(datapath.id, i)
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, priority=80, match=match, actions=actions)
                if self.debug:
                    print(f"[ADDING FLOW] {self._dpid_to_name(datapath.id)} - Downward Rule: Match 10.{pod_x}.{i}.0/24 -> Port {out_port}")

            # 2. Upward Load-Balancing (Suffix-Match)
            # Ziel: 0.0.0.i/8 -> Suffix-Routing per OpenFlow Arbitrary Bitmask
            # Maske 0.0.0.255 ignoriert die ersten 3 Oktette und matcht exakt die Host-ID.
            for host_id in range(2, k_half + 2):
                match = datapath.ofproto_parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_dst=(f'0.0.0.{host_id}', '0.0.0.255')
                )
                # Formel: (i - 2 + z) mod (k/2) + (k/2)
                # 1. Logischen Uplink-Index berechnen (Welcher Pfad nach oben?)

                uplink_index = (host_id - 2 + switch_z) % k_half

                # 2. Topologie-Abfrage: Alle Core-Switches finden, die an diesen Agg-Switch hängen
                connected_switches = self.adjacency.get(datapath.id, {})
                connected_cores = []
                
                for peer_dpid in connected_switches.keys():
                    peer_meta = self.switch_info.get(peer_dpid)
                    if peer_meta and peer_meta.get('type') == 'core':
                        connected_cores.append(peer_dpid)
                
                # Deterministische Sortierung nach der IP-Adresse des Core-Switches
                # lambda-Funktion Holt die IP aus switch_info; Fallback auf leeren String, falls nicht gesetzt
                connected_cores.sort(
                    key=lambda dpid: self.switch_info.get(dpid, {}).get('ip', '')
                )
                # 3. Den spezifischen Core-Switch für diesen Flow auswählen
                target_core_dpid = connected_cores[uplink_index]

                # 4. Den echten OpenFlow-Port aus der Topologie (z.B. NetworkX Graph) auflösen
                out_port = self.adjacency[datapath.id][target_core_dpid]

                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, priority=60, match=match, actions=actions)

            # 3. Default-Route (Catch-All für restlichen Upward-Traffic)
            # Ziel: 0.0.0.0/0
            # Hier droppen wir den Traffic aber eigentlich kann man hiermit ins internet gaten etc
            match = datapath.ofproto_parser.OFPMatch(eth_type=0x0800)
            actions = []
            self.add_flow(datapath, priority=40, match=match, actions=actions)

        if sw_meta['type'] == 'edge':
            if self.debug:
                print(f"[INSTALL FLOW EDGE] switch {self._dpid_to_name(datapath.id)} baut flow rules auf")
            
            #------------------------------------------------------#
            # DOWNSTREAM FORWARDING / ARP RESOLUTION
            #-------------------------------------------------------#
            msg = ev.msg
            
            dst_ip = ipv4_pkt.dst if ipv4_pkt else None

            if dst_ip:
                # Extrahiere die IP-Oktette zur Subnetz-Prüfung
                ip_octets = dst_ip.split('.')
                pod = int(ip_octets[1])
                subnet = int(ip_octets[2])

                # Prüfen, ob das Ziel im L2-Zuständigkeitsbereich dieses Switches liegt
                is_local_subnet = (pod == sw_meta['pod'] and subnet == sw_meta['idx'])

                if is_local_subnet:
                    #-------------------------------------------------------#
                    # DOWNSTREAM: Ziel ist im lokalen /24-Subnetz
                    #-------------------------------------------------------#
                    known_port = self.host_port_table.get(dpid, {}).get(dst_ip)
                    # Fallback: Falls die Hardware-Regel noch nicht greift (Race Condition) 
                    # oder es ein ARP-Request für ein bekanntes Ziel ist.
                    if known_port:
                        actions = [datapath.ofproto_parser.OFPActionOutput(known_port)]
                        out = datapath.ofproto_parser.OFPPacketOut(
                            datapath=datapath, buffer_id=msg.buffer_id,
                            in_port=in_port, actions=actions,
                            data=msg.data if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
                        )
                        datapath.send_msg(out)
                    else:
                        # Ziel unbekannt: Broadcast/Flood an lokales Subnetz delegieren
                        if self.debug:
                            print(f"[EDGE-FLOOD] {self._dpid_to_name(dpid)}: Unbekanntes Ziel {dst_ip}, flutet an Hosts und buffer message.")
                        # Buffer message nicht löschen, damit die Hosts direkt antworten können (z.B. ARP-Request)
                        self.pending_messages.setdefault(dpid, []).append((msg, in_port))
                        self._send_arp_request(
                        datapath=datapath, 
                        target_ip=dst_ip, 
                        sw_meta=sw_meta
                    )

            #------------------------------------------------------#
            # Upward Routing (Suffix-Match) zu den Aggregation-Switches
            #-------------------------------------------------------#
            # 1. Metadaten des aktuellen Edge-Switches bestimmen
            pod_x = sw_meta['pod']
            switch_z = sw_meta['idx'] # Index z in [0, k/2 - 1]
            
            k_half = self.k // 2

            # 2. Topologie-Abfrage: Alle direkt verbundenen Aggregation-Switches ermitteln
            connected_switches = self.adjacency.get(datapath.id, {})
            connected_aggs = []
            
            for peer_dpid in connected_switches.keys():
                peer_meta = self.switch_info.get(peer_dpid)
                if peer_meta and peer_meta.get('type') == 'agg':
                    connected_aggs.append(peer_dpid)
            
            # Deterministische Sortierung nach IP-Adresse, damit die Port-Indizes stimmen
            connected_aggs.sort(
                key=lambda dpid: self.switch_info.get(dpid, {}).get('ip', '')
            )

            # Laut Paper (Section 3.5): Der Edge-Switch verteilt den gesamten Inter-Subnetz-Traffic 
            # mittels Suffix-Matching gleichmäßig nach oben.
            for host_id in range(2, k_half + 2):
                match = datapath.ofproto_parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_dst=(f'0.0.0.{host_id}', '0.0.0.255')
                )
                if len(connected_aggs) < k_half:
                    if self.debug: print(f"[WARN] {self._dpid_to_name(datapath.id)}: Adjazenz unvollständig. Warte auf LLDP.")
                    return
                # Der logische Uplink-Index (0 bis k/2 - 1) bestimmt den zuständigen Agg-Switch.

                #For the lower pod switches, we simply omit the /24 subnet prefix
                #step, in line 3, since that subnet’s own traffic is switched, and
                #intra- and inter-pod traffic should be evenly split among the upper
                #switches.
                uplink_index = (host_id - 2 + switch_z) % k_half
                
                # Ziel-Aggregation-Switch aus der sortierten Liste wählen
                target_agg_dpid = connected_aggs[uplink_index]
                
                # Physischen Ausgangsport aus self.adjacency auflösen
                out_port = self.adjacency[datapath.id][target_agg_dpid]
                
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                self.add_flow(datapath, priority=60, match=match, actions=actions)

    def _dpid_to_name(self, dpid):
        """
        Rekonstruiert die logischen Namen (c0, p0a0, p0e0) für Logging/Debugging,
        obwohl Mininet intern 's{dpid}' verwendet.
        """
        n = self.k // 2
        core_limit = n * n
        agg_limit = core_limit + (self.k * n)

        if 1 <= dpid <= core_limit:
            return f"c{dpid - 1}"
            
        elif core_limit < dpid <= agg_limit:
            offset = dpid - core_limit - 1
            return f"p{offset // n}a{offset % n}"
            
        elif agg_limit < dpid:
            offset = dpid - agg_limit - 1
            return f"p{offset // n}e{offset % n}"
            
        return f"s{dpid}"
    
    def _resolve_core_to_pod_port(self, core_dpid, target_pod):
        """
        Löst den Egress-Port eines Core-Switches zum Ziel-Pod auf.
        Suche in den adjazenten Knoten.
        """
        for peer_dpid, port_no in self.adjacency.get(core_dpid, {}).items():
            peer_meta = self.switch_info.get(peer_dpid)
            if peer_meta and peer_meta.get('type') == 'agg' and peer_meta.get('pod') == target_pod:
                return port_no
        return None

    def _resolve_agg_to_edge_port(self, agg_dpid, dst_subnet):
        """
        Löst den Egress-Port eines Aggregation-Switches zum Edge-Switch (Subnetz) auf.
        """
        for peer_dpid, port_no in self.adjacency.get(agg_dpid, {}).items():
            peer_meta = self.switch_info.get(peer_dpid)
            if peer_meta and peer_meta.get('type') == 'edge' and peer_meta.get('idx') == dst_subnet:
                return port_no
        return None


    def _handle_arp_request(self, datapath, port, eth, arp_pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Einheitliche virtuelle MAC für alle Router-Interfaces im Fat-Tree
        router_mac = "00:00:00:00:00:fe"
        
        # ARP-Reply Payload generieren
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype,
                                           dst=eth.src,
                                           src=router_mac))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                 src_mac=router_mac,
                                 src_ip=arp_pkt.dst_ip,
                                 dst_mac=arp_pkt.src_mac,
                                 dst_ip=arp_pkt.src_ip))
        pkt.serialize()
        
        # Direkter PacketOut an den Ingress-Port
        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER,
                                  actions=actions,
                                  data=pkt.data)
        datapath.send_msg(out)


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

    def _is_host_port(self, dpid, port):
        """Prüft strikt, ob der Ingress-Port ein Endhost-Port ist. Blockiert bei unvollständiger Topologie."""
        inter_switch_ports = self.adjacency.get(dpid, {}).values()
        if len(inter_switch_ports) < (self.k // 2):
            if self.debug:
                print(f"[DISCOVERY] {self._dpid_to_name(dpid)} LLDP noch nicht konvergiert -> Schutz vor Table-Poisoning")
            return False # LLDP noch nicht konvergiert -> Schutz vor Table-Poisoning
        return port not in inter_switch_ports

    def _extract_src_ip(self, pkt):
        """Extrahiert zustandslos die IPv4-Quelladresse aus dem Packet-Payload."""
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            return arp_pkt.src_ip
        
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            return ipv4_pkt.src
            
        return None

    def _install_host_downward_flow(self, datapath, target_ip, target_mac, out_port):
        """Injiziert die Hardware-Route (Prio 100) für spezifischen Downstream-Traffic."""
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(
            eth_type=0x0800, 
            ipv4_dst=target_ip
        )
        # Echte MAC des physischen Switch-Ports ermitteln
        # Fallback auf die virtuelle MAC, falls der Port im Dict fehlt
        port_obj = datapath.ports.get(out_port)
        src_mac = port_obj.hw_addr if port_obj else "00:00:00:00:00:fe"
        
        actions = [
            datapath.ofproto_parser.OFPActionSetField(eth_dst=target_mac),
            datapath.ofproto_parser.OFPActionSetField(eth_src=src_mac),
            datapath.ofproto_parser.OFPActionDecNwTtl(),
            parser.OFPActionOutput(out_port)
        ]
        # Priority 100 überschreibt Suffix-Upstream (60) und Default-Drop (40)
        self.add_flow(datapath, priority=100, match=match, actions=actions)

    def _flood_to_hosts(self, datapath, msg, in_port, dst_ip=None):
        """
        Leitet das Paket gezielt per Unicast an den bekannten Host-Port weiter.
        Falls die Ziel-IP unbekannt ist (oder es sich um einen L2-Broadcast handelt),
        wird ein Flood an alle verbleibenden Host-Ports durchgeführt (Split-Horizon).
        """
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # 1. Prüfen, ob der Ziel-Port für diese IP bereits dynamisch gelernt wurde
        known_data = None
        if dst_ip:
            known_data = self.host_port_table.get(dpid, {}).get(dst_ip)

        if known_data:
            # OPTIMIERUNG: Host ist bekannt -> Unicast statt Flood
            # Da wir in Szenario A (L3-Routing) sind, fügen wir hier direkt das MAC-Rewrite ein,
            # falls die Ziel-MAC des Pakets noch die Gateway-MAC ist.
            target_port = known_data['port']
            target_mac = known_data['mac']
            
            actions = [
                parser.OFPActionSetField(eth_dst=target_mac),
                parser.OFPActionOutput(target_port)
            ]
            if self.debug:
                print(f"[EDGE-UNICAST] {self._dpid_to_name(dpid)}: Ziel {dst_ip} bekannt. Sende Unicast an Port {target_port}")
        else:
            # FALLBACK: Ziel ist unbekannt -> Klassischer Subnetz-Flood an alle Host-Ports
            host_ports = self._get_host_facing_ports(datapath)
            
            actions = [parser.OFPActionOutput(p) for p in host_ports]
            if self.debug:
                print(f"[EDGE-FLOOD] {self._dpid_to_name(dpid)}: Ziel {dst_ip} unbekannt. Flute an Ports: {host_ports}")

        # 2. Packet-Out konstruieren und absenden
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    def _get_host_facing_ports(self, datapath):
        """Isoliert die Downlink-Ports zum Edge durch Subtraktion der Fabric-Links."""
        dpid = datapath.id
        ofproto = datapath.ofproto
        
        # 1. Alle bekannten Fabric-Ports (Uplinks/Inter-Switch-Links) aus der Adjazenzliste
        fabric_ports = set(self.adjacency.get(dpid, {}).values())

        if len(fabric_ports) < (self.k // 2):
            if self.debug:
                print(f"{self._dpid_to_name(datapath.id)} noch nicht genug ports gefunden")
            return [] # Split-Horizon-Schutz: Verhindert ARP-Storms in die Fabric

        # 2. Alle physischen Ports direkt aus dem Datapath-Objekt auslesen
        # datapath.ports ist ein Dict: {port_no: Port-Objekt}
        # Wir filtern Ports >= OFPP_MAX (z.B. OFPP_LOCAL, was Portnummer 0xfffffffe ist)
        all_ports = set(
            p.port_no for p in datapath.ports.values() 
            if p.port_no < ofproto.OFPP_MAX
        )
        
        # 3. Differenzmenge = Host-Facing Ports
        return list(all_ports - fabric_ports)
    
    
