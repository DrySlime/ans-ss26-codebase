from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp, udp
import logging

class PacketDebugger:
    """
    Utility-Klasse für tiefe Paketinspektion und formatiertes Logging im SDN-Kontext.
    """
    def __init__(self, logger):
        self.log = logger

    def trace(self, msg_data, dpid, context, port=None, reason=None):
        """
        Hauptmethode zum Loggen eines Pakets an beliebigen Stellen in der Pipeline.
        
        :param msg_data: msg.data vom OpenFlow Event
        :param dpid: Datapath ID des aktuellen Switches/Routers
        :param context: String (z.B. "INGRESS", "EGRESS", "DROP", "BUFFERED")
        :param port: Ingress- oder Egress-Port
        :param reason: Optionaler String zur Begründung (z.B. "Security Policy", "Table Miss")
        """
        pkt = packet.Packet(msg_data)
        
        # Header extrahieren
        eth = pkt.get_protocol(ethernet.ethernet)
        a = pkt.get_protocol(arp.arp)
        ip = pkt.get_protocol(ipv4.ipv4)
        t = pkt.get_protocol(tcp.tcp)
        u = pkt.get_protocol(udp.udp)
        i = pkt.get_protocol(icmp.icmp)

        if not eth:
            self.log.debug(f"[DPID: {dpid} | {context}] Malformed Packet (No Ethernet Header)")
            return

        # 1. Base Log: Switch, Event-Kontext und Port
        log_str = f"[DPID:{dpid} | {context:^7}] "
        if port:
            log_str += f"Port:{port:<2} | "

        # 2. Layer 2 (Ethernet)
        log_str += f"L2[{eth.src} -> {eth.dst}] "

        # 3. Layer 2.5 (ARP)
        if a:
            op = "REQ" if a.opcode == arp.ARP_REQUEST else "REP" if a.opcode == arp.ARP_REPLY else str(a.opcode)
            log_str += f"| ARP-{op}[{a.src_ip} -> {a.dst_ip}] "

        # 4. Layer 3 (IPv4)
        if ip:
            log_str += f"| L3[{ip.src} -> {ip.dst} | TTL:{ip.ttl} | Proto:{ip.proto}] "

        # 5. Layer 4 (TCP/UDP/ICMP)
        if t:
            flags = self._tcp_flags(t.bits)
            log_str += f"| TCP[{t.src_port} -> {t.dst_port} | Flags:{flags}]"
        elif u:
            log_str += f"| UDP[{u.src_port} -> {u.dst_port}]"
        elif i:
            log_str += f"| ICMP[Type:{i.type} Code:{i.code}]"

        # 6. Reason (Optional, nützlich für Drops)
        if reason:
            log_str += f" >>> REASON: {reason}"

        # Ausgabe auf INFO-Level für Sichtbarkeit im Ryu-Standard-Log
        self.log.info(log_str)

    def _tcp_flags(self, bits):
        """Bitweise Dekodierung der TCP-Flags."""
        flags = []
        if bits & 0x02: flags.append("SYN")
        if bits & 0x10: flags.append("ACK")
        if bits & 0x01: flags.append("FIN")
        if bits & 0x04: flags.append("RST")
        if bits & 0x08: flags.append("PSH")
        if bits & 0x20: flags.append("URG")
        return ",".join(flags) if flags else "NONE"