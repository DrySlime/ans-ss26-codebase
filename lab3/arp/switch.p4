#include <core.p4>
#include <v1model.p4>

const bit<16> ETH_TYPE_ARP = 0x0806;
const bit<16> ARP_REQUEST = 1;
const bit<16> ARP_REPLY   = 2;
const bit<32> PKT_INSTANCE_TYPE_REPLICATION = 5;

header ethernet_t {
  bit<48> dstAddr;
  bit<48> srcAddr;
  bit<16> etherType;
}

header arp_t {
  bit<16> hrd; // Hardware type
  bit<16> pro; // Protocol type
  bit<8>  hln; // Hardware address length
  bit<8>  pln; // Protocol address length
  bit<16> op;  // Opcode (request/reply)
  bit<48> sha; // Sender hardware address (MAC)
  bit<32> spa; // Sender protocol address (IP)
  bit<48> tha; // Target hardware address (MAC)
  bit<32> tpa; // Target protocol address (IP)
}

struct headers_t {
  ethernet_t ethernet;
  arp_t      arp;
}

struct metadata_t { }

parser parse(packet_in pkt, out headers_t hdr,
             inout metadata_t meta, inout standard_metadata_t std) {
  state start {
    pkt.extract(hdr.ethernet);
    transition select(hdr.ethernet.etherType) {
      ETH_TYPE_ARP: parse_arp;
      default: accept;
    }
  }
  state parse_arp {
    pkt.extract(hdr.arp);
    transition accept;
  }
}

control ingress(inout headers_t hdr,
                inout metadata_t meta, inout standard_metadata_t std) {

  register<bit<16>>(1) flood_mgid;

  action flood() {
    flood_mgid.read(std.mcast_grp, 0);
  }

  action forward(bit<9> port) {
    std.egress_spec = port;
  }

  action arp_reply(bit<48> target_mac) {
    // Swap Ethernet source/destination MAC addresses
    hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
    hdr.ethernet.srcAddr = target_mac;

    // Change opcode to reply
    hdr.arp.op = ARP_REPLY;

    // Swap ARP MAC and IP addresses
    bit<32> target_ip = hdr.arp.tpa;
    hdr.arp.tha = hdr.arp.sha;
    hdr.arp.tpa = hdr.arp.spa;
    hdr.arp.sha = target_mac;
    hdr.arp.spa = target_ip;

    // Send packet back to the ingress port
    std.egress_spec = std.ingress_port;
  }

  table dmac {
    key = {
      hdr.ethernet.dstAddr: exact;
    }
    actions = {
      forward;
      flood;
      NoAction;
    }
    size = 1024;
    default_action = flood();
  }

  table arp_table {
    key = {
      hdr.arp.tpa: exact;
    }
    actions = {
      arp_reply;
      NoAction;
    }
    size = 1024;
    default_action = NoAction;
  }

  apply {
    if (hdr.arp.isValid() && hdr.arp.op == ARP_REQUEST) {
      arp_table.apply();
    } else {
      dmac.apply();
    }
  }
}

control egress(inout headers_t hdr,
               inout metadata_t meta, inout standard_metadata_t std) {
  apply {
    // Drop packet if it is being sent back out of the ingress port (loopback filtering during flooding)
    if (std.instance_type == PKT_INSTANCE_TYPE_REPLICATION &&
        std.egress_port == std.ingress_port) {
      mark_to_drop(std);
    }
  }
}

control deparse(packet_out pkt, in headers_t hdr) {
  apply {
    pkt.emit(hdr.ethernet);
    pkt.emit(hdr.arp);
  }
}

control no_checksum(inout headers_t hdr, inout metadata_t meta) { apply {  } }

V1Switch(parse(),no_checksum(),ingress(),egress(),no_checksum(),deparse()) main;

