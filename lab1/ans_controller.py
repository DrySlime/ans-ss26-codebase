"""
 Copyright (c) 2026 Computer Networks Group @ UPB

 Permission is hereby granted...
 """

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet, arp, ipv4

class Router(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Router, self).__init__(*args, **kwargs)
        
        # Router port MACs assumed by the controller
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }
        # Router port (gateways) IP addresses assumed by the controller
        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }
        self.arp_table = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        # Nur Router-Datapath verarbeiten
        if datapath.id != 3:
            return

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        
        # Chris NOTE: This is where we will implement the routing logic for switch s3. 
        # https://datatracker.ietf.org/doc/html/rfc1812 ... this is our rfc and from there I found these TASKS
        msg = ev.msg
        datapath = msg.datapath

        is_not_router = datapath.id != 3
        if is_not_router:
            return
            
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        if arp_pkt:
            self.handle_arp_request(arp_pkt, in_port, ev, pkt)
        if ipv4_pkt:
            self.handle_ipv4_packet(ipv4_pkt, in_port)

    def handle_arp_request(self, arp_pkt, in_port, ev, pkt):
        # 1. ARP Request/Reply lernen: IP in MAC übersetzen und speichern
        self.arp_table[arp_pkt.src_ip] = arp_pkt.src_mac
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        eth_pkt = pkt.get_protocol(ethernet.ethernet)

        # 2. Wenn es ein Request an die Router-IP ist, generiere einen ARP Reply
        is_arp_request = arp_pkt.opcode == arp.ARP_REQUEST
        is_arp_intended_for_router = arp_pkt.dst_ip == self.port_to_own_ip.get(in_port)

        if is_arp_request and is_arp_intended_for_router:
            self.logger.info(f"Received ARP Request for {arp_pkt.dst_ip} on port {in_port}, building ARP Reply...")
            
            router_mac = self.port_to_own_mac.get(in_port)
            router_ip = self.port_to_own_ip.get(in_port)

            reply_pkt = packet.Packet()

            eth_reply = ethernet.ethernet(
                dst=eth_pkt.src,               # Zurück an die anfragende MAC
                src=router_mac,                # Router MAC als Absender
                ethertype=ether.ETH_TYPE_ARP   # Typ 0x0806
            )
            reply_pkt.add_protocol(eth_reply)

            arp_reply = arp.arp(
                hwtype=1,                      
                proto=0x0800,                  
                hlen=6,                        
                plen=4,                        
                opcode=arp.ARP_REPLY,          
                src_mac=router_mac,            
                src_ip=router_ip,              
                dst_mac=arp_pkt.src_mac,       
                dst_ip=arp_pkt.src_ip          
            )
            reply_pkt.add_protocol(arp_reply)
            reply_pkt.serialize()

            # TODO i copied this code snippet without understanding it...
            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=reply_pkt.data
            )
            
            datapath.send_msg(out)

    def handle_ipv4_packet(self, ipv4_pkt, in_port):
        # TODO Task 1: IP Header verification (RFC 1812 Section 5.2.2)
        pass
        
        # TODO Task 2: Determining the Next Hop Address (RFC 1812 Section 5.2.4)
        dst_ip = ipv4_pkt.dst
        
        if dst_ip in self.arp_table:
            dst_mac = self.arp_table[dst_ip]
            # Modifiziere src/dst MAC und leite Paket weiter
        else:
            # MAC unbekannt: Generiere ARP Request und puffere oder droppe das IP-Paket
            pass

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'router': Router}

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        
        # Ignoriere den Router-Datapath
        is_router = datapath.id == 3
        if is_router:
            return

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
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


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # Chris NOTE: You can find this code snippet https://osrg.github.io/ryu-book/en/html/switching_hub.html.
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        # Router-Traffic ignorieren
        if dpid == 3:
            return

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.mac_to_port.setdefault(dpid, {})

        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        
        # Chris NOTE: We extract the source and destination MAC address...
        if not eth_pkt:
            return
            
        dst = eth_pkt.dst
        src = eth_pkt.src
        in_port = msg.match['in_port']

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        # NOTE: here is an example entry
        # 1: { dpid des ersten Switches (s1)
        # '00:00:00:00:00:01': 1, # Host A ist an Port 1
        # '00:00:00:00:00:02': 2  # Host B ist an Port 2
        # }
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:            
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # Chris NOTE: This test is basically saying if the destination port doesnt equal FF:FF:... , then we can install a flow entry for it. 
        if out_port != ofproto.OFPP_FLOOD:
            #Chris NOTE: that will be the matchrule for the flow entry.
            # The table entry will now have a entry somewhat like | (Port) 1: (Dst) 00:00:00:00:00:01
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)


