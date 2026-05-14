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
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.packet import packet, ethernet, arp, ipv4, in_proto, icmp
import ipaddress


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        self.forwarding_tables = {}  # Dictionary for each switch
        self.router_arp_table = {}  # Dictionary for the ARP table on the router
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03",
        }
        self.port_to_own_ip = {1: "10.0.1.1", 2: "10.0.2.1", 3: "192.168.1.1"}
        self.routing_table = {
            ipaddress.IPv4Network("10.0.1.0/24"): 1,
            ipaddress.IPv4Network("10.0.2.0/24"): 2,
            ipaddress.IPv4Network("192.168.1.0/24"): 3,
        }
        self.pending_packets = {}

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

        # Policy flows on router
        if datapath.id == 3:
            self.install_icmp_policy_flows(datapath)
            self.install_tcp_udp_policy_flows(datapath)
            self.install_gateway_policy_flows(datapath)

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

        frame = packet.Packet(msg.data).get_protocol(ethernet.ethernet)
        arpMessage = packet.Packet(msg.data).get_protocol(arp.arp)
        ipPacket = packet.Packet(msg.data).get_protocol(ipv4.ipv4)
        icmpMessage = packet.Packet(msg.data).get_protocol(icmp.icmp)

        # ARP for gateway MAC
        if arpMessage and arpMessage.dst_ip in self.port_to_own_ip.values():
            # save IP/MAC combination
            self.router_arp_table[arpMessage.src_ip] = arpMessage.src_mac

            # If router gets an ARP request
            if arpMessage.opcode == 1:
                arpPacket = self.create_arp_packet(
                    self.port_to_own_ip[inPort],
                    arpMessage.src_ip,
                    self.port_to_own_mac[inPort],
                    arpMessage.src_mac,
                    isRequest=False,
                )
                actions = [datapath.ofproto_parser.OFPActionOutput(inPort)]

                self.send_packet(
                    datapath=datapath,
                    bufferId=datapath.ofproto.OFP_NO_BUFFER,
                    inPort=datapath.ofproto.OFPP_CONTROLLER,  # packet comes from controller
                    actionOutputs=actions,
                    data=arpPacket.data,
                )

            # If router gets an ARP Reply
            elif arpMessage.opcode == 2:
                # send pending packets if any exist
                if arpMessage.src_ip in self.pending_packets:
                    packets = self.pending_packets.pop(arpMessage.src_ip)
                    outPort = packets[0][1]

                    # same flow for rewriting packets for that dstMAC
                    actions = self.install_router_flow(
                        datapath,
                        self.port_to_own_mac[outPort],
                        arpMessage.src_mac,
                        arpMessage.src_ip,
                        outPort,
                    )

                    for msg, _ in packets:
                        self.send_packet(
                            datapath=datapath,
                            bufferId=datapath.ofproto.OFP_NO_BUFFER,
                            inPort=datapath.ofproto.OFPP_CONTROLLER,  # packet comes from controller
                            actionOutputs=actions,
                            data=msg.data,
                        )

        # Ping Reply for gateway
        elif (
            ipPacket
            and frame
            and ipPacket.dst in self.port_to_own_ip.values()
            and icmpMessage
            and icmpMessage.type == icmp.ICMP_ECHO_REQUEST
        ):
            icmpPacket = self.create_icmp_packet(
                self.port_to_own_mac[inPort],
                frame.src,
                self.port_to_own_ip[inPort],
                ipPacket.src,
                icmpMessage.data,
                isRequest=False,
            )
            actions = [datapath.ofproto_parser.OFPActionOutput(inPort)]

            self.send_packet(
                datapath=datapath,
                bufferId=datapath.ofproto.OFP_NO_BUFFER,
                inPort=datapath.ofproto.OFPP_CONTROLLER,  # packet comes from controller
                actionOutputs=actions,
                data=icmpPacket.data,
            )

        # Routing IP Packets to correct Port
        elif ipPacket:
            outPort = self.find_longest_matching_prefix(ipPacket.dst)

            if ipPacket.dst not in self.router_arp_table:
                # save packet for later
                if ipPacket.dst not in self.pending_packets:
                    self.pending_packets[ipPacket.dst] = []
                self.pending_packets[ipPacket.dst].append((msg, outPort))

                # ARP for dst IP
                arpPacket = self.create_arp_packet(
                    self.port_to_own_ip[outPort],
                    ipPacket.dst,
                    self.port_to_own_mac[outPort],
                    "ff:ff:ff:ff:ff:ff",
                    isRequest=True,
                )
                actions = [datapath.ofproto_parser.OFPActionOutput(outPort)]

                self.send_packet(
                    datapath=datapath,
                    bufferId=datapath.ofproto.OFP_NO_BUFFER,
                    inPort=datapath.ofproto.OFPP_CONTROLLER,  # packet comes from controller
                    actionOutputs=actions,
                    data=arpPacket.data,
                )
            else:
                # if the dstMAC is already in the table, we can rewrite the frame directly
                actions = self.install_router_flow(
                    datapath,
                    self.port_to_own_mac[outPort],
                    self.router_arp_table[ipPacket.dst],
                    ipPacket.dst,
                    outPort,
                )
                self.send_packet(
                    datapath=datapath,
                    bufferId=datapath.ofproto.OFP_NO_BUFFER,
                    inPort=datapath.ofproto.OFPP_CONTROLLER,  # packet comes from controller
                    actionOutputs=actions,
                    data=msg.data,
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

        # If destMAC already known, create flow and forward
        if destMAC in self.forwarding_tables[switchId]:
            actions = [
                datapath.ofproto_parser.OFPActionOutput(
                    self.forwarding_tables[switchId][destMAC]
                )
            ]
            match = datapath.ofproto_parser.OFPMatch(eth_dst=destMAC, in_port=inPort)
            self.add_flow(datapath, 1, match, actions)
        # If not, flood
        else:
            actions = [
                datapath.ofproto_parser.OFPActionOutput(datapath.ofproto.OFPP_FLOOD)
            ]
        self.send_packet(
            datapath, datapath.ofproto.OFP_NO_BUFFER, inPort, actions, msg.data
        )

    def install_router_flow(self, datapath, srcMAC, dstMAC, dstIP, outPort):
        actions = [
            datapath.ofproto_parser.OFPActionSetField(eth_src=srcMAC),
            datapath.ofproto_parser.OFPActionSetField(eth_dst=dstMAC),
            datapath.ofproto_parser.OFPActionOutput(outPort),
        ]

        # since we know the dstMAC, we can create a flow for rewriting the packtes
        match = datapath.ofproto_parser.OFPMatch(
            eth_type=ether.ETH_TYPE_IP, ipv4_dst=dstIP
        )
        self.add_flow(datapath, 10, match, actions)

        return actions

    def install_icmp_policy_flows(self, datapath):
        ext_net = next(net for net, port in self.routing_table.items() if port == 3)
        int_nets = [net for net, port in self.routing_table.items() if port in (1, 2)]

        for int_net in int_nets:
            # external to internal
            match = datapath.ofproto_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ip_proto=in_proto.IPPROTO_ICMP,
                icmpv4_type=icmp.ICMP_ECHO_REQUEST,
                # apply subnet mask by converting to tuple
                ipv4_src=(str(ext_net.network_address), str(ext_net.netmask)),
                ipv4_dst=(str(int_net.network_address), str(int_net.netmask)),
            )
            self.add_flow(datapath, 100, match, [])

            # internal to external
            match = datapath.ofproto_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ip_proto=in_proto.IPPROTO_ICMP,
                icmpv4_type=icmp.ICMP_ECHO_REQUEST,
                ipv4_src=(str(int_net.network_address), str(int_net.netmask)),
                ipv4_dst=(str(ext_net.network_address), str(ext_net.netmask)),
            )
            self.add_flow(datapath, 100, match, [])

    def install_tcp_udp_policy_flows(self, datapath):
        ext_net = next(net for net, port in self.routing_table.items() if port == 3)
        ser_net = next(net for net, port in self.routing_table.items() if port == 2)

        for proto in (in_proto.IPPROTO_TCP, in_proto.IPPROTO_UDP):
            # external to server
            match = datapath.ofproto_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ip_proto=proto,
                # apply subnet mask by converting to tuple
                ipv4_src=(str(ext_net.network_address), str(ext_net.netmask)),
                ipv4_dst=(str(ser_net.network_address), str(ser_net.netmask)),
            )
            self.add_flow(datapath, 100, match, [])

            # server to external
            match = datapath.ofproto_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ip_proto=proto,
                ipv4_src=(str(ser_net.network_address), str(ser_net.netmask)),
                ipv4_dst=(str(ext_net.network_address), str(ext_net.netmask)),
            )
            self.add_flow(datapath, 100, match, [])

    def install_gateway_policy_flows(self, datapath):
        for in_port in self.port_to_own_ip:
            for out_port, gateway_ip in self.port_to_own_ip.items():
                # install flow rule when ping doesnt go the same port/gateway where its coming from
                if in_port != out_port:
                    match = datapath.ofproto_parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether.ETH_TYPE_IP,
                        ip_proto=in_proto.IPPROTO_ICMP,
                        icmpv4_type=icmp.ICMP_ECHO_REQUEST,
                        ipv4_dst=gateway_ip,
                    )
                    self.add_flow(datapath, 100, match, [])

    def send_packet(self, datapath, bufferId, inPort, actionOutputs, data):
        ofp_parser = datapath.ofproto_parser
        out = ofp_parser.OFPPacketOut(datapath, bufferId, inPort, actionOutputs, data)
        datapath.send_msg(out)

    def create_arp_packet(self, srcIP, dstIP, srcMAC, dstMAC, isRequest: bool):
        pkt = packet.Packet()
        ethHeader = ethernet.ethernet(
            dst=dstMAC, src=srcMAC, ethertype=ether.ETH_TYPE_ARP  # ARP Code
        )
        arpHeader = arp.arp(
            dst_ip=dstIP,
            src_ip=srcIP,
            dst_mac="00:00:00:00:00:00" if isRequest else dstMAC,
            src_mac=srcMAC,
            opcode=1 if isRequest else 2,  # 1 = request; 2 = response
        )
        pkt.add_protocol(ethHeader)
        pkt.add_protocol(arpHeader)
        pkt.serialize()
        return pkt

    def create_icmp_packet(
        self, srcMAC, dstMAC, srcIP, dstIP, icmpData, isRequest: bool
    ):
        pkt = packet.Packet()
        ethHeader = ethernet.ethernet(
            dst=dstMAC,
            src=srcMAC,
            ethertype=ether.ETH_TYPE_IP,
        )
        ipHeader = ipv4.ipv4(
            dst=dstIP,
            src=srcIP,
            proto=in_proto.IPPROTO_ICMP,
        )
        # set Type to Ping request/reply
        icmpHeader = icmp.icmp(
            type_=icmp.ICMP_ECHO_REQUEST if isRequest else icmp.ICMP_ECHO_REPLY,
            code=(
                icmp.ICMP_ECHO_REQUEST_CODE if isRequest else icmp.ICMP_ECHO_REPLY_CODE
            ),
            csum=0,
            data=icmpData,
        )

        pkt.add_protocol(ethHeader)
        pkt.add_protocol(ipHeader)
        pkt.add_protocol(icmpHeader)
        pkt.serialize()
        return pkt

    def find_longest_matching_prefix(self, ip):
        ip_address = ipaddress.IPv4Address(ip)
        current_max_length = 0
        port = None

        for network, outPort in self.routing_table.items():
            if ip_address in network and network.prefixlen > current_max_length:
                port = outPort
                current_max_length = network.prefixlen

        return port

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
