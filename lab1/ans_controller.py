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
from ryu.lib.packet import packet, ethernet


class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)

        # Here you can initialize the data structures you want to keep at the controller
        self.mac_to_port = {}
        

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    # Handle the packet_in event
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        #Chris NOTE: You can find this code snippet https://osrg.github.io/ryu-book/en/html/switching_hub.html. Guys try to learn and understand each line of code
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        if self._is_a_router(dpid):
            # L3 Routing Logik für s3
            self._handle_router_packet(ev)
        else:
            # Bestehende L2 Learning Switch Logik für s1 und s2
            self._handle_switch_packet(ev)
    
    def _is_a_router(self, dpid):
        return dpid == 3
    
    def _handle_router_packet(self, ev):
        # Chris NOTE: This is where we will implement the routing logic for switch s3. 
        # https://datatracker.ietf.org/doc/html/rfc1812 ... this is our rfc and from there I found these TASKS

        # Task 1 Packet Forwarding; 
        #       IP Header verification (RFC 1812 Section 5.2.2), 
        #       TTL processing (RFC 1812 Section 5.3.1),
        #       Determining the Next Hop Address (RFC 1812 Section 5.2.4),
        #       ARP resolution (RFC 1812 Section 3.3.2),


        # Router port MACs assumed by the controller
        port_to_own_mac = {
        1: "00:00:00:00:01:01",
        2: "00:00:00:00:01:02",
        3: "00:00:00:00:01:03"
        }
        # Router port (gateways) IP addresses assumed by the controller
        port_to_own_ip = {
        1: "10.0.1.1",
        2: "10.0.2.1",
        3: "192.168.1.1"
        }

        pass

    def _handle_switch_packet(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        # Chris NOTE: We extract the source and destination MAC address from the Ethernet header of the packet
        # here in the ethernet protocol layer.
        dst = eth_pkt.dst
        src = eth_pkt.src
        
        # get the received port number from packet_in message.
        in_port = msg.match['in_port']

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        # NOTE: here is an example entry
        # 1: { dpid des ersten Switches (s1)
        # '00:00:00:00:00:01': 1, # Host A ist an Port 1
        # '00:00:00:00:00:02': 2  # Host B ist an Port 2
        # }
        self.mac_to_port[dpid][src] = in_port

        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:            
            out_port = ofproto.OFPP_FLOOD

        # construct action list.
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time.
        # Chris NOTE: Rhis test is basically saying if the destination port doesnt equal FF:FF:... , then we can install a flow entry for it. 
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

# Chris NOTE: May the routing begin! https://osrg.github.io/ryu-book/en/html/rest_router.html
# So first I tried reading the guide and here i am, supposed to start an xterm c1 and build a bridge here... 
# this should be also able to be done programmatically.
#  I found this