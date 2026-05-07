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

from ans_switch import LearningSwitch
from ans_router import Router


class MainController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MainController, self).__init__(*args, **kwargs)
        self.switch_logic = LearningSwitch(*args, **kwargs)
        self.router_logic = Router(*args, **kwargs)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dpid = ev.msg.datapath.id
        
        if dpid == 3:
            self.router_logic.switch_features_handler(ev)
        else:
            self.switch_logic.switch_features_handler(ev)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        dpid = ev.msg.datapath.id
        
        if dpid == 3:
            self.router_logic._packet_in_handler(ev)
        else:
            self.switch_logic._packet_in_handler(ev)

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def _flow_removed_handler(self, ev):
        dpid = ev.msg.datapath.id
        
        # Router hat in der ans_router.py keinen FlowRemoved-Handler implementiert.
        # Daher nur für Switches relevant.
        if dpid != 3:
            self.switch_logic._flow_removed_handler(ev)
        else:
            self.router_logic._flow_removed_handler(ev)