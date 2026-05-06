"""
Copyright (c) 2026 Computer Networks Group @ UPB

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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        self.forwarding_tables = {}  # Dictionary for each switch
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03",
        }
        self.port_to_own_ip = {1: "10.0.1.1", 2: "10.0.2.1", 3: "192.168.1.1"}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, instructions=inst
        )
        datapath.send_msg(mod)

    def perform_router_logic(self, msg):
        datapath = msg.datapath
        inPort = msg.match["in_port"]

        # frame = packet.Packet(msg.data).get_protocol(ethernet.ethernet)
        arpMessage = packet.Packet(msg.data).get_protocol(arp.arp)
        # ipPacket = packet.Packet(msg.data).get_protocol(ipv4.ipv4)
        # icmpMessage = packet.Packet(msg.data).get_protocol(icmp.icmp)

        if (
            arpMessage
            and arpMessage.opcode == 1
            and arpMessage.dst_ip in self.port_to_own_ip.values()
        ):
            pkt = packet.Packet()
            ethHeader = ethernet.ethernet(
                dst=arpMessage.src_mac,
                src=self.port_to_own_mac[inPort],
                ethertype=0x0806,  # ARP CODE
            )
            arpHeader = arp.arp(
                dst_ip=arpMessage.src_ip,
                src_ip=self.port_to_own_ip[inPort],
                dst_mac=arpMessage.src_mac,
                src_mac=self.port_to_own_mac[inPort],
                opcode=2,
            )
            pkt.add_protocol(ethHeader)
            pkt.add_protocol(arpHeader)
            pkt.serialize()
            actions = [datapath.ofproto_parser.OFPActionOutput(inPort)]
            self.sendPacket(
                datapath=datapath,
                bufferId=datapath.ofproto.OFP_NO_BUFFER,
                inPort=datapath.ofproto.OFPP_CONTROLLER,  # no port, because packet comes from controller
                actionOutputs=actions,
                data=pkt.data,
            )

    def perform_switch_logic(self, msg):
        datapath = msg.datapath
        switchId = datapath.id

        frame = packet.Packet(msg.data).get_protocol(ethernet.ethernet)
        sourceMAC = frame.src
        destMAC = frame.dst
        inPort = msg.match["in_port"]

        if switchId not in self.forwarding_tables:
            self.forwarding_tables[switchId] = {}

        self.forwarding_tables[switchId][sourceMAC] = inPort

        # just set the port
        if destMAC in self.forwarding_tables[switchId]:
            actions = [
                datapath.ofproto_parser.OFPActionOutput(
                    self.forwarding_tables[switchId][destMAC]
                )
            ]
            match = datapath.ofproto_parser.OFPMatch(eth_dst=destMAC, in_port=inPort)
            self.add_flow(datapath, 1, match, actions)
        else:
            actions = [
                datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)
            ]
        self.sendPacket(
            datapath, datapath.ofproto.OFP_NO_BUFFER, inPort, actions, msg.data
        )

    def sendPacket(self, datapath, bufferId, inPort, actionOutputs, data):
        ofp_parser = datapath.ofproto_parser
        out = ofp_parser.OFPPacketOut(datapath, bufferId, inPort, actionOutputs, data)
        datapath.send_msg(out)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        switchId = datapath.id

        # Router logic
        if switchId == 3:
            self.perform_router_logic(msg)

        # Switch logic
        else:
            self.perform_switch_logic(msg)

        for switch, table in self.forwarding_tables.items():
            print(f"Switch {switch}:")
            for mac, port in table.items():
                print(f"  {mac} -> port {port}")
        print("-----------------------------------")
