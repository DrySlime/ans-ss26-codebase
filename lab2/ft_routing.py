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

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet, ipv4, arp, ethernet

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase

import topo


class FTRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FTRouter, self).__init__(*args, **kwargs)

        self.k = 4
        # Fattree class, NOT FattreeNet -> contains the switches NODES and EDGES
        self.topo_net = topo.Fattree(self.k)

        # Maps the DPID = index to the Topo node data
        self.switch_info = {
            index: switch
            for index, switch in enumerate(self.topo_net.switches, start=1)
        }

        # to which switch (dpid) and port is the host IP connected
        self.host_locations = {}

        # contains the port, a SWITCH is connected to an other
        self.link_ports = {}

        # contains all ports of switches, connected to a HOST
        self.host_ports = {}

        # contains the datapath for a dpid for installing flows later
        self.datapaths = {}

        # Flag, whether the flows are already installed for not installing them twice
        self.routes_installed = False

    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        # Switches and links in the network
        switches = get_switch(self, None)
        links = get_link(self, None)

        for switch in switches:
            dpid = switch.dp.id
            self.datapaths[dpid] = switch.dp

        for link in links:
            # add the port, two SWITCHES are connected with (via LLDP)
            self.link_ports[(link.src.dpid, link.dst.dpid)] = link.src.port_no
            self.link_ports[(link.dst.dpid, link.src.dpid)] = link.dst.port_no

        for switch in switches:
            dpid = switch.dp.id
            all_ports = {
                port.port_no
                for port in switch.ports
                if port.port_no < ofproto_v1_3.OFPP_MAX
            }
            switch_to_switch_ports = {
                port
                for (src_dpid, _), port in self.link_ports.items()
                if src_dpid == dpid
            }
            self.host_ports[dpid] = all_ports - switch_to_switch_ports

        if (
            len(self.datapaths) == 5 * self.k * self.k // 4  # expected switches
            and len(self.link_ports) // 2
            == self.k**3 // 2  # expected links between switches
            and not self.routes_installed
        ):
            self._install_routes()
            self.routes_installed = True

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install entry-miss flow entry
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        frame = packet.Packet(msg.data).get_protocol(ethernet.ethernet)
        arp_message = packet.Packet(msg.data).get_protocol(arp.arp)
        ip_packet = packet.Packet(msg.data).get_protocol(ipv4.ipv4)

        if frame is None:
            return

        if frame.ethertype in (ether.ETH_TYPE_LLDP, ether.ETH_TYPE_IPV6):
            return

        if arp_message:
            self._handleARP(msg, dpid, in_port)
        # elif ip_packet:
        #     self._handleIPv4(msg, dpid, in_port)

    def _handleARP(self, msg, source_dpid, in_port):
        arp_message = packet.Packet(msg.data).get_protocol(arp.arp)

        if arp_message.src_ip not in self.host_locations.keys():
            self.host_locations[arp_message.src_ip] = (source_dpid, in_port)
            datapath = self.datapaths[source_dpid]

            # install flow rule once host location is present
            match = datapath.ofproto_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ipv4_dst=(arp_message.src_ip, "255.255.255.255"),
            )
            actions = [datapath.ofproto_parser.OFPActionOutput(in_port)]
            self.add_flow(datapath, 30, match, actions)

        # For ARP Reply
        if arp_message.dst_ip in self.host_locations.keys():
            # send arp directly to edge switch and host port
            destination_dpid, destination_port = self.host_locations[arp_message.dst_ip]
            datapath = self.datapaths[destination_dpid]

            actions = [datapath.ofproto_parser.OFPActionOutput(destination_port)]
            self._send_packet(
                datapath=datapath,
                bufferId=datapath.ofproto.OFP_NO_BUFFER,
                inPort=datapath.ofproto.OFPP_CONTROLLER,
                actionOutputs=actions,
                data=msg.data,
            )
        # For ARP Request
        else:
            # flood to all hosts except the one sending the arp
            for dpid, ports in self.host_ports.items():
                datapath = self.datapaths[dpid]
                actions = [
                    datapath.ofproto_parser.OFPActionOutput(port)
                    for port in ports
                    if not (dpid == source_dpid and port == in_port)
                ]
                self._send_packet(
                    datapath=datapath,
                    bufferId=datapath.ofproto.OFP_NO_BUFFER,
                    inPort=datapath.ofproto.OFPP_CONTROLLER,
                    actionOutputs=actions,
                    data=msg.data,
                )

    def _send_packet(self, datapath, bufferId, inPort, actionOutputs, data):
        ofp_parser = datapath.ofproto_parser
        out = ofp_parser.OFPPacketOut(datapath, bufferId, inPort, actionOutputs, data)
        datapath.send_msg(out)

    def _install_routes(self):
        for dpid, node in self.switch_info.items():
            datapath = self.datapaths[dpid]

            if node.type == "core":
                agg_dpids = [
                    dst_dpid
                    for src_dpid, dst_dpid in self.link_ports.keys()
                    if src_dpid == dpid
                ]
                # install /16 flow for each pod from core switch
                for agg_dpid in agg_dpids:
                    agg_node = self.switch_info[agg_dpid]
                    pod = agg_node.id.split("_")[1]
                    out_port = self.link_ports[(dpid, agg_dpid)]

                    match = datapath.ofproto_parser.OFPMatch(
                        eth_type=ether.ETH_TYPE_IP,
                        ipv4_dst=(f"10.{pod}.0.0", "255.255.0.0"),
                    )
                    actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                    self.add_flow(datapath, 20, match, actions)

            elif node.type == "aggregation":
                pod = node.id.split("_")[1]
                # normalize: k/2 -> k-1 to 0 -> k/2 -1s
                agg_position = int(node.id.split("_")[3]) - self.k // 2
                edge_dpids = [
                    dst_dpid
                    for src_dpid, dst_dpid in self.link_ports.keys()
                    if src_dpid == dpid and self.switch_info[dst_dpid].type == "edge"
                ]
                core_dpids = [
                    dst_dpid
                    for src_dpid, dst_dpid in self.link_ports.keys()
                    if src_dpid == dpid and self.switch_info[dst_dpid].type == "core"
                ]
                core_dpids.sort(key=lambda core_dpid: self.switch_info[core_dpid].id)
                # install prefix flow rule /24 for forwarding to edge switch
                for edge_dpid in edge_dpids:
                    edge_node = self.switch_info[edge_dpid]
                    edge_id = edge_node.id.split("_")[3]
                    out_port = self.link_ports[(dpid, edge_dpid)]

                    match = datapath.ofproto_parser.OFPMatch(
                        eth_type=ether.ETH_TYPE_IP,
                        ipv4_dst=(f"10.{pod}.{edge_id}.0", "255.255.255.0"),
                    )
                    actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                    self.add_flow(datapath, 20, match, actions)

                for host_id in range(2, self.k // 2 + 2):
                    # normalize host id and include agg position to distribute same hosts
                    # to different cores depending on the agg switch
                    core_index = (host_id - 2 + agg_position) % (self.k // 2)
                    core_dpid = core_dpids[core_index]
                    out_port = self.link_ports[(dpid, core_dpid)]

                    match = datapath.ofproto_parser.OFPMatch(
                        eth_type=ether.ETH_TYPE_IP,
                        ipv4_dst=(f"0.0.0.{host_id}", "0.0.0.255"),
                    )
                    actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                    # lower priority 10 for matching to edge switches before to core switches
                    self.add_flow(datapath, 10, match, actions)

            elif node.type == "edge":
                pod = node.id.split("_")[1]
                edge_position = int(node.id.split("_")[3])

                agg_dpids = [
                    dst_dpid
                    for src_dpid, dst_dpid in self.link_ports.keys()
                    if src_dpid == dpid
                    and self.switch_info[dst_dpid].type == "aggregation"
                ]
                agg_dpids.sort(key=lambda agg_dpid: self.switch_info[agg_dpid].id)

                # install suffix flow rule for matching on host id
                for host_id in range(2, self.k // 2 + 2):
                    agg_index = (host_id - 2 + edge_position) % (self.k // 2)
                    agg_dpid = agg_dpids[agg_index]
                    out_port = self.link_ports[(dpid, agg_dpid)]

                    match = datapath.ofproto_parser.OFPMatch(
                        eth_type=ether.ETH_TYPE_IP,
                        ipv4_dst=(f"0.0.0.{host_id}", "0.0.0.255"),
                    )
                    actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                    # lower priority 10 for matching to hosts before to agg switches
                    self.add_flow(datapath, 10, match, actions)
