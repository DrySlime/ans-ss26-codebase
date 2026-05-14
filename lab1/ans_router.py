"""
 Copyright (c) 2026 Computer Networks Group @ UPB

 Permission is hereby granted...
 """

from ryu.base import app_manager
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, in_proto
import ipaddress # perfect for bit logical operations on IP addresses and subnet masks, e.g., for LPM lookups or later hostmask in Datacenters
from packet_debugger import PacketDebugger


class Router(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Router, self).__init__(*args, **kwargs)
        self.debugger = PacketDebugger(self.logger)
        self.router_configs = {
            3: { # Router 1 (DPID 3)
                'macs': {1: "00:00:00:00:01:01", 2: "00:00:00:00:01:02", 3: "00:00:00:00:01:03"},
                'ips': {1: "10.0.1.1", 2: "10.0.2.1", 3: "192.168.1.1"},
                'routes': {
                    ipaddress.IPv4Network("10.0.1.0/24"): 1,
                    ipaddress.IPv4Network("10.0.2.0/24"): 2,
                    ipaddress.IPv4Network("192.168.1.0/24"): 3
                }
            }
        }        
        self.arp_table = {} # Struktur: {dpid: {ip: mac}}
        # buffer with the structure {dpid: {ipaddress: (msg, in_port, out_port, pkt)}}
        self.pending_packets = {}

    def _flow_removed_handler(self, ev):
        pass

    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.apply_security_policy(datapath)

        # Table-Miss Flow für den Router
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

    # --- HELPER FUNKTIONEN FÜR PAKETGENERIERUNG UND DISPATCHING ---

    def _send_packet_out(self, datapath, out_port, data, in_port=None):
        """Kapselt das Versenden eines Pakets über einen spezifischen Port aus dem Controller."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = in_port if in_port is not None else ofproto.OFPP_CONTROLLER
        actions = [parser.OFPActionOutput(out_port)]
        
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    def _build_arp_packet(self, src_mac, dst_mac_eth, target_mac_arp, src_ip, dst_ip, opcode):
        """Generiert generisch ARP-Requests oder -Replies als Byte-Array."""
        pkt = packet.Packet()
        eth_header = ethernet.ethernet(dst=dst_mac_eth, src=src_mac, ethertype=ether.ETH_TYPE_ARP)
        arp_header = arp.arp(
            hwtype=1, proto=ether.ETH_TYPE_IP, hlen=6, plen=4,
            opcode=opcode, src_mac=src_mac, src_ip=src_ip, 
            dst_mac=target_mac_arp, dst_ip=dst_ip
        )
        pkt.add_protocol(eth_header)
        pkt.add_protocol(arp_header)
        pkt.serialize()
        return pkt.data

    def _build_icmp_packet(self, src_mac, dst_mac, src_ip, dst_ip, icmp_type, icmp_code, icmp_data):
        """Generiert generisch ICMP-Pakete (Echo Reply oder Errors) als Byte-Array."""
        pkt = packet.Packet()
        eth_header = ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether.ETH_TYPE_IP)
        ip_header = ipv4.ipv4(dst=dst_ip, src=src_ip, proto=in_proto.IPPROTO_ICMP)
        icmp_header = icmp.icmp(type_=icmp_type, code=icmp_code, csum=0, data=icmp_data)
        
        pkt.add_protocol(eth_header)
        pkt.add_protocol(ip_header)
        pkt.add_protocol(icmp_header)
        pkt.serialize()
        return pkt.data

    def _generate_icmp_error(self, datapath, port, original_pkt, eth_pkt, ipv4_pkt, icmp_code):
        """Zentrale Logik für ICMP Destination Unreachable Errors (Type 3) inkl. RFC 792 Payload-Extraktion."""
        dpid = datapath.id
        src_mac = self.router_configs[dpid]['macs'].get(port)
        src_ip = self.router_configs[dpid]['ips'].get(port)

        # RFC 792 Extraction: IP-Header + erste 8 Bytes des ICMP-Payloads aus dem Raw-Buffer
        eth_offset = 18 if eth_pkt.ethertype == ether.ETH_TYPE_8021Q else 14
        ip_hlen = ipv4_pkt.header_length * 4
        orig_ip_bytes = original_pkt.data[eth_offset : eth_offset + ip_hlen + 8]
        
        unreach_data = icmp.dest_unreach(data_len=len(orig_ip_bytes), data=orig_ip_bytes)
        
        pkt_data = self._build_icmp_packet(
            src_mac=src_mac, dst_mac=eth_pkt.src,
            src_ip=src_ip, dst_ip=ipv4_pkt.src,
            icmp_type=icmp.ICMP_DEST_UNREACH, icmp_code=icmp_code, icmp_data=unreach_data
        )
        self._send_packet_out(datapath, port, pkt_data)

    # --- CORE ROUTING LOGIK ---

    def _packet_in_handler(self, ev):
        # Chris NOTE: This handler will be called for every packet that matches the table-miss flow entry, 
        # i.e., for every packet that doesn't match any existing flow entry in the switch. 
        # This is where we implement our learning switch and routing logic.
        # https://datatracker.ietf.org/doc/html/rfc1812 ... this is our rfc for routing behavior, we should follow it as closely as possible.
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        
        self.arp_table.setdefault(dpid, {})
        self.pending_packets.setdefault(dpid, {})
        
        # THis is the way I found to extract the incoming port.  
        in_port = msg.match['in_port']

        # Debugging
        self.debugger.trace(msg.data, datapath.id, "INGRESS", port=in_port)

        pkt = packet.Packet(msg.data)
        
        # This is a neat way to extract the different protocol layers from the packet. 
        # We can then check if the packet contains an ARP, IPv4, or Ethernet header and process
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        if not eth_pkt:
            return

        # 1. L2-Validierung: Router verarbeitet nur L2-Broadcasts oder Unicasts an sein eigenes Interface
        router_mac = self.router_configs[dpid]['macs'].get(in_port)
        if eth_pkt.dst != 'ff:ff:ff:ff:ff:ff' and eth_pkt.dst != router_mac:
            # Paket ignorieren (Drop), da es auf L2 nicht an den Router adressiert ist. 
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            self.handle_arp_packet(arp_pkt, in_port, ev, pkt)
        if ipv4_pkt:
            self.handle_ipv4_packet(ipv4_pkt, in_port, ev, pkt)
    
    def apply_security_policy(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid = datapath.id

        # 1. Dynamische Extraktion als IPv4Network-Objekte
        ext_net_obj = next(net for net, port in self.router_configs[dpid]['routes'].items() if port == 3) # WAN 
        ser_net_obj = next(net for net, port in self.router_configs[dpid]['routes'].items() if port == 2) # Servernet

        # 2. Konvertierung in Ryu-kompatible String-Tupel ("Netzwerk-IP", "Subnetzmaske")
        ext_net = (str(ext_net_obj.network_address), str(ext_net_obj.netmask))
        ser_net = (str(ser_net_obj.network_address), str(ser_net_obj.netmask))

        # 3. Diese pakete sind laut Sicherheitsrichtlinie verboten, 
        # wir installieren also eine Regel mit hoher Priorität, 
        # die diese Pakete an den Controller puntet, 
        # damit wir sie dort richtig bearbeiten und beantworten können.
        punt_actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        
        # --- A) Punting-Regeln für TCP/UDP (Prio 100) ---
        for proto in [in_proto.IPPROTO_TCP, in_proto.IPPROTO_UDP]:
            # ext -> ser blockieren und an Controller übergeben
            match_ext_to_ser = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=proto, ipv4_src=ext_net, ipv4_dst=ser_net)
            self.add_flow(datapath, 100, match_ext_to_ser, punt_actions)

            # ser -> ext blockieren und an Controller übergeben
            match_ser_to_ext = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ip_proto=proto, ipv4_src=ser_net, ipv4_dst=ext_net)
            self.add_flow(datapath, 100, match_ser_to_ext, punt_actions)

        # --- B) Hardware-Offloading für Gateway-Schutz ---
        # Iteriere über alle Router-Ports. Installiere eine punt-Regel für jeden Ingress-Port, 
        # wenn die Ziel-IP der IP eines *anderen* Router-Ports entspricht.
        for in_port, _ in self.router_configs[dpid]['ips'].items():
            for other_port, other_ip in self.router_configs[dpid]['ips'].items():
                if in_port != other_port:
                    match_gw_drop = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether.ETH_TYPE_IP,
                        ip_proto=in_proto.IPPROTO_ICMP,
                        icmpv4_type=8,
                        ipv4_dst=other_ip # Ziel ist fremdes Gateway
                    )
                    self.add_flow(datapath, 100, match_gw_drop, punt_actions)

    def handle_arp_packet(self, arp_pkt, in_port, ev, pkt):
        # 1. ARP Request/Reply learning: IP in MAC translate and save
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id  

        self.arp_table[dpid][arp_pkt.src_ip] = arp_pkt.src_mac

        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        is_arp_request = arp_pkt.opcode == arp.ARP_REQUEST
        is_arp_intended_for_router = arp_pkt.dst_ip == self.router_configs[dpid]['ips'].get(in_port)
        is_arp_response = arp_pkt.opcode == arp.ARP_REPLY

        # If the ARP request is for the router's own IP, we need to reply with an ARP response identifying us.
        if is_arp_request and is_arp_intended_for_router:
            self._send_arp_reply(datapath, in_port, arp_pkt, eth_pkt)
        elif is_arp_response:
            # Gepufferte Pakete abrufen und weiterleiten
            # if there is a queue for the source ip          
            if arp_pkt.src_ip in self.pending_packets[dpid]:
                self._send_pending_packets(dpid, arp_pkt.src_ip, arp_pkt.src_mac)                        
                del self.pending_packets[dpid][arp_pkt.src_ip]

    def _send_pending_packets(self, dpid, src_ip, dst_mac):
        for queued_msg, q_in_port, q_out_port, q_pkt in self.pending_packets[dpid][src_ip]:
            datapath = queued_msg.datapath
            parser = datapath.ofproto_parser
            q_ipv4 = q_pkt.get_protocol(ipv4.ipv4)
            src_mac = self.router_configs[dpid]['macs'].get(q_out_port)
            
            actions = [
                parser.OFPActionSetField(eth_src=src_mac),
                parser.OFPActionSetField(eth_dst=dst_mac),
                parser.OFPActionDecNwTtl(),
                parser.OFPActionOutput(q_out_port)
            ]
            
            # Hardware Offloading für zukünftige Pakete dieses Flows
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=q_ipv4.src, ipv4_dst=q_ipv4.dst)
            self.add_flow(datapath, 10, match, actions)
            
            data = q_pkt.data if queued_msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=queued_msg.buffer_id,
                in_port=q_in_port, actions=actions, data=data
            )
            datapath.send_msg(out)

    def _send_arp_reply(self, datapath, in_port, arp_pkt, eth_pkt):
        # based on the incoming port, we determine the router's own MAC and IP address that we need to use in the ARP reply.
        dpid = datapath.id
        router_mac = self.router_configs[dpid]['macs'].get(in_port)
        router_ip = self.router_configs[dpid]['ips'].get(in_port)

        pkt_data = self._build_arp_packet(
            src_mac=router_mac, dst_mac_eth=eth_pkt.src, target_mac_arp=arp_pkt.src_mac,
            src_ip=router_ip, dst_ip=arp_pkt.src_ip, opcode=arp.ARP_REPLY
        )
        self._send_packet_out(datapath, in_port, pkt_data)

    def _send_arp_request(self, datapath, out_port, dst_ip):
        dpid = datapath.id
        src_mac = self.router_configs[dpid]['macs'].get(out_port)
        src_ip = self.router_configs[dpid]['ips'].get(out_port)
        
        self.logger.info(f"Generating ARP Request for {dst_ip} on port {out_port} with source IP {src_ip} and source MAC {src_mac}")
        
        pkt_data = self._build_arp_packet(
            src_mac=src_mac, dst_mac_eth='ff:ff:ff:ff:ff:ff', target_mac_arp='00:00:00:00:00:00',
            src_ip=src_ip, dst_ip=dst_ip, opcode=arp.ARP_REQUEST
        )
        self._send_packet_out(datapath, out_port, pkt_data)

    def send_icmp_prohibited(self, datapath, port, original_pkt, eth_pkt, ipv4_pkt):
        # Type 3 (Dest Unreachable), Code 13 (Admin Prohibited)
        self._generate_icmp_error(datapath, port, original_pkt, eth_pkt, ipv4_pkt, 13)

    def send_icmp_network_unreachable(self, datapath, port, original_pkt, eth_pkt, ipv4_pkt):
        # Type 3 (Dest Unreachable), Code 0 (Network Unreachable)
        self._generate_icmp_error(datapath, port, original_pkt, eth_pkt, ipv4_pkt, 0)

    def handle_ipv4_packet(self, ipv4_pkt, in_port, ev, pkt):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        # --- START: ICMP Filter-Logik ---
        if ipv4_pkt.proto == in_proto.IPPROTO_ICMP:
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            # Chris NOTE: we check if it's an ICMP Echo Request and then apply our security policy to decide whether to drop it or not.
            if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                src_ip_obj = ipaddress.IPv4Address(src_ip)
                dst_ip_obj = ipaddress.IPv4Address(dst_ip)
                
                routes = self.router_configs[dpid]['routes']
                ext_nets = [net for net, port in routes.items() if port == 3]
                int_nets = [net for net, port in routes.items() if port in (1, 2)]
                
                ext_to_int = any(src_ip_obj in net for net in ext_nets) and any(dst_ip_obj in net for net in int_nets)
                int_to_ext = any(src_ip_obj in net for net in int_nets) and any(dst_ip_obj in net for net in ext_nets)
                
                if ext_to_int or int_to_ext:
                    self.logger.info(f"Security Policy: Drop ICMP Echo Request {src_ip} -> {dst_ip}")
                    self.send_icmp_prohibited(datapath, in_port, pkt, eth_pkt, ipv4_pkt)
                    return  # Packet Drop
                
        # --- START: TCP/UDP Filter-Logik ---
        # Chris NOTE: Den blockierten TCP/UDP Traffic Pakete hier abfangen und senden den geforderten ICMP Prohibited.
        if ipv4_pkt.proto in (in_proto.IPPROTO_TCP, in_proto.IPPROTO_UDP):
            src_ip_obj = ipaddress.IPv4Address(src_ip)
            dst_ip_obj = ipaddress.IPv4Address(dst_ip)
            
            routes = self.router_configs[dpid]['routes']
            ext_nets = [net for net, port in routes.items() if port == 3]
            ser_nets = [net for net, port in routes.items() if port == 2]
            
            ext_to_ser = any(src_ip_obj in net for net in ext_nets) and any(dst_ip_obj in net for net in ser_nets)
            ser_to_ext = any(src_ip_obj in net for net in ser_nets) and any(dst_ip_obj in net for net in ext_nets)
            
            if ext_to_ser or ser_to_ext:
                self.send_icmp_prohibited(datapath, in_port, pkt, eth_pkt, ipv4_pkt)
                return  # Verhindert das weitere Routing dieses Pakets.

        # 2.1 LPM Routing lookup
        out_port = self.find_longest_prefix_match(dpid, dst_ip)

        # 2.2 If no route found, drop packet
        if out_port is None:
            self.logger.info("Keine Route für %s gefunden. Dropping packet.", dst_ip)
            self.send_icmp_network_unreachable(datapath, in_port, pkt, eth_pkt, ipv4_pkt)
            return
        
        # 2.3 Ziel-IP ist direkt an einem Router-Port angeschlossen: ICMP Echo Request erlauben, alle anderen Pakete verbieten
        if dst_ip in self.router_configs[dpid]['ips'].values():
            if dst_ip != self.router_configs[dpid]['ips'].get(in_port):
                self.send_icmp_prohibited(datapath, in_port, pkt, eth_pkt, ipv4_pkt)
            else:
                self.handle_icmp_echo_request(ipv4_pkt, in_port, datapath, pkt)
            return

        #----------------------------Ab hier ist die normale Routing-Logik für Pakete, die nicht direkt an den Router adressiert sind.----------------------------

        # Prüfe Next-Hop MAC in ARP-Tabelle
        if dst_ip in self.arp_table[dpid]:
            self._send_pkt_next_hop(datapath, msg, src_ip, dst_ip, in_port, out_port, pkt)        
        else: # 2.4 Next-Hop MAC unbekannt: ARP Request generieren und Paket puffern
            if dst_ip not in self.pending_packets[dpid]:
                self.pending_packets[dpid][dst_ip] = []
                self._send_arp_request(datapath, out_port, dst_ip)  
            # Paket puffern              
            self.pending_packets[dpid][dst_ip].append((msg, in_port, out_port, pkt))
            
        # Someone is trying to ping the router itself, we should reply with an ICMP Echo Reply if it's an Echo Request.   
        if dst_ip == self.router_configs[dpid]['ips'].get(in_port):
            self.handle_icmp_echo_request(ipv4_pkt, in_port, datapath, pkt)
            return

    def _send_pkt_next_hop(self, datapath, msg, src_ip, dst_ip, in_port, out_port, pkt):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        dpid = datapath.id
        dst_mac = self.arp_table[dpid][dst_ip]
        src_mac = self.router_configs[dpid]['macs'][out_port]

        # Actions für Forwarding: Src/Dst MAC umschreiben, TTL verringern, an out_port senden
        actions = [
            parser.OFPActionSetField(eth_src=src_mac),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionDecNwTtl(), # checksum is actually calculated here in this function also.
            parser.OFPActionOutput(out_port)
        ]

        # Flow Entry generieren (Hardware Offloading für diesen Pfad)
        match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IP, ipv4_src=src_ip, ipv4_dst=dst_ip)
        self.add_flow(datapath, 10, match, actions)

        # Controller muss aktuelles Paket ebenfalls weiterleiten
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )
        datapath.send_msg(out)

    def handle_icmp_echo_request(self, ipv4_pkt, in_port, datapath, pkt):   
        # Paket ist direkt an den Router adressiert. Erwarte ICMP Echo Request.
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst_ip = ipv4_pkt.dst
        
        # if it's an ICMP Echo Request, we generate an Echo Reply. For any other type of traffic to the router's own IP, we simply ignore it (drop).
        if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
            self.send_icmp_reply(datapath, in_port, eth_pkt, ipv4_pkt, icmp_pkt)
        else:
            self.logger.info(f"IPv4 traffic to router IP {dst_ip} ignored (not ICMP Echo Request).")
        
    def find_longest_prefix_match(self, dpid, dst_ip):
        # Chris NOTE: we iterate through the routing table and check if the destination IP falls within any of the CIDR blocks. If it does, we check if it's the longest prefix match so far. If it is, we remember that as our best match and the corresponding output port.
        best_match = None
        out_port = None
        dst_ip_obj = ipaddress.IPv4Address(dst_ip)
        routes = self.router_configs[dpid]['routes']

        for net, port in routes.items():
            # Chris NOTE: the ipaddress module allows us to easily check if an IP address belongs to a network using the 'in' operator, which internally handles the bitwise operations needed for CIDR matching.
            if dst_ip_obj in net:
                if best_match is None or net.prefixlen > best_match.prefixlen:
                    best_match = net
                    out_port = port
                
        return out_port

    def send_icmp_reply(self, datapath, port, eth_pkt, ipv4_pkt, icmp_pkt):
        # einfach ping echo
        dpid = datapath.id
        pkt_data = self._build_icmp_packet(
            src_mac=self.router_configs[dpid]['macs'].get(port), dst_mac=eth_pkt.src,
            src_ip=self.router_configs[dpid]['ips'].get(port), dst_ip=ipv4_pkt.src,
            icmp_type=icmp.ICMP_ECHO_REPLY, icmp_code=icmp.ICMP_ECHO_REPLY_CODE, icmp_data=icmp_pkt.data
        )
        self._send_packet_out(datapath, port, pkt_data)