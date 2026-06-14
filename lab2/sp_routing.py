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
from ryu.lib import hub
from ryu.lib.packet import packet, ipv4, arp, ethernet

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase

import topo


class SPRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)

        # Initialize the topology with #ports=4
        self.topo_net = topo.Fattree(4)

        # to which switch (dpid) and port is the host IP connected
        self.host_locations = {}

        # contains the port, a SWITCH is connected to an other
        self.link_ports = {}

        # contains all ports of switches, connected to a HOST
        self.host_ports = {}

        # contains the datapath for a dpid for installing flows later
        self.datapaths = {}

        # contains the connected dpid's
        self.graph = {}

        # Flag for indicating, whether the flow rules are already installed
        self.routes_installed = False

    # Topology discovery gets called if new switch/link appear
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        # Switches and links in the network
        switches = get_switch(self, None)
        links = get_link(self, None)

        for switch in switches:
            dpid = switch.dp.id
            self.datapaths[dpid] = switch.dp

            # create new key in dict [] -> {}, if not exists
            self.graph.setdefault(dpid, set())

        for link in links:
            # add all the SWITCHES which can reach each other(via LLDP)
            self.graph.setdefault(link.src.dpid, set()).add(link.dst.dpid)
            self.graph.setdefault(link.dst.dpid, set()).add(link.src.dpid)

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

    # Gets called for every packet a switch hadnt a flow for
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handle(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id  # ryu switch id
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
        elif ip_packet:
            self._handleIPv4(msg, dpid, in_port)

    def _handleARP(self, msg, source_dpid, in_port):
        arp_message = packet.Packet(msg.data).get_protocol(arp.arp)

        if arp_message.src_ip not in self.host_locations.keys():
            self.host_locations[arp_message.src_ip] = (source_dpid, in_port)

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

    def _handleIPv4(self, msg, src_dpid, in_port):
        ip_packet = packet.Packet(msg.data).get_protocol(ipv4.ipv4)

        if ip_packet.dst not in self.host_locations.keys():
            return

        dst_dpid, dst_port = self.host_locations[ip_packet.dst]
        # forward packets through the path and install flows on switches
        path = self._shortest_path(src_dpid, dst_dpid)
        if not path:
            return

        for index, dpid in enumerate(path):
            datapath = self.datapaths[dpid]

            # if arrived at the last switch = dst edge switch
            if index == len(path) - 1:
                out_port = dst_port
            else:
                # get port to next switch
                out_port = self.link_ports[(dpid, path[index + 1])]

            match = datapath.ofproto_parser.OFPMatch(
                eth_type=ether.ETH_TYPE_IP,
                ipv4_dst=ip_packet.dst,
            )
            actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 10, match, actions)

            # send packet on the first switch manually, on following ones the flow rule cares
            if index == 0:
                self._send_packet(
                    datapath=datapath,
                    bufferId=msg.buffer_id,
                    inPort=in_port,
                    actionOutputs=actions,
                    data=msg.data,
                )

    def _send_packet(self, datapath, bufferId, inPort, actionOutputs, data):
        ofp_parser = datapath.ofproto_parser
        out = ofp_parser.OFPPacketOut(datapath, bufferId, inPort, actionOutputs, data)
        datapath.send_msg(out)

    def _shortest_path(self, start, destination):
        # set all nodes to infinity
        distances = {node: float("inf") for node in self.graph}
        previous = {node: None for node in self.graph}
        # start with all nodes
        unvisited = set(self.graph)

        distances[start] = 0

        while unvisited:
            # extract node with smallest distance and remove it from unvisited since the distance cant get smaller anymore
            current = min(unvisited, key=lambda node: distances[node])

            if distances[current] == float("inf"):
                return None

            if current == destination:
                break

            unvisited.remove(current)

            # set the distance to neighbors, if the current path achieves a smaller distance
            for neighbor in self.graph[current]:
                if neighbor not in unvisited:
                    continue

                new_distance = distances[current] + 1

                if new_distance < distances[neighbor]:
                    distances[neighbor] = new_distance
                    previous[neighbor] = current

        path = []
        # start at the end
        current = destination

        # go along the "parents" to reach the start and remember all nodes
        while current is not None:
            path.append(current)
            current = previous[current]

        # reverse the path to begin at the start
        path.reverse()

        if not path or path[0] != start:
            return None

        return path
