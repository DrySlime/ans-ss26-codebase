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

# Chris NOTE: Efectively we intent to implement a simple CAM table learning switch

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {} # our CAM table \ Content Addressable Memory
        print("LearningSwitch Ryu App initialized.")

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
        mod = parser.OFPFlowMod(
            datapath=datapath, #our tcp connection to the switch
            priority=priority,  # higher priority = more specific match rule                             
            match=match, # the matching rule from layer 2 to layer 4
            instructions=inst # the instruction to apply
            # CHRIS NOTE: i found this logic to implement some way of freshness of the flow entries
            #hard_timeout=600,    # basically 10 minutes for the flow entry to expire
            #flags=ofproto.OFPFF_SEND_FLOW_REM # Zwingend für State-Sync, this will call the flow_removed_handler
            )
        datapath.send_msg(mod)

    # Chris NOTE: This handler will be called when a flow entry expires (idle_timeout) or is removed (hard_timeout) and will be used to clean up our CAM table entries.
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        msg = ev.msg
        dpid = msg.datapath.id
        
        # Extraktion der Ziel-MAC aus dem Match der abgelaufenen Regel
        mac = msg.match.get('eth_dst') 
        
        if dpid in self.mac_to_port and mac in self.mac_to_port[dpid]:
            self.logger.info(f"Flow expired: Removing MAC {mac} from DPID {dpid}")
            del self.mac_to_port[dpid][mac]

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

        # this is our layer 2 forwarding action
        # basically just forward the packet to the output port if we know it
        actions = [parser.OFPActionOutput(out_port)]

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


