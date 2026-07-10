#include <core.p4>
#include <v1model.p4>

#define CHUNK_SIZE 2

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header switchml_t {
    bit<32> chunk_id;
    bit<16> rank;
    bit<16> num_workers;
    bit<16> chunk_len;
    int<32> val0;
    int<32> val1;
    int<32> val2;
    int<32> val3;
    int<32> val4;
    int<32> val5;
}

struct headers_t {
    ethernet_t eth;
    ipv4_t     ipv4;
    udp_t      udp;
    switchml_t switchml;
}

struct metadata_t { }

parser parse(packet_in pkt, out headers_t hdr,
             inout metadata_t meta, inout standard_metadata_t std) {
    state start {
        pkt.extract(hdr.eth);
        transition select(hdr.eth.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp;
            default: accept;
        }
    }
    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            0xbee0: parse_switchml;
            default: accept;
        }
    }
    state parse_switchml {
        pkt.extract(hdr.switchml);
        transition accept;
    }
}

control ingress(inout headers_t hdr, inout metadata_t meta,
                inout standard_metadata_t std) {

    register<bit<16>>(1) flood_mgid;

    // SwitchML registers (for W<=32, slot size = 64)
    register<bit<32>>(64) expected_chunk_id;
    register<bit<16>>(64) count;
    register<bit<32>>(64) bitmap;
    register<int<32>>(64) pool0;
    register<int<32>>(64) pool1;
    register<int<32>>(64) pool2;
    register<int<32>>(64) pool3;
    register<int<32>>(64) pool4;
    register<int<32>>(64) pool5;

    action flood() {
        flood_mgid.read(std.mcast_grp, 0);
    }

    action forward(bit<9> port) {
        std.egress_spec = port;
    }

    table dmac {
        key = {
            hdr.eth.dstAddr: exact;
        }
        actions = {
            forward;
            flood;
            NoAction;
        }
        size = 1024;
        default_action = flood();
    }

    apply {
        if (hdr.switchml.isValid()) {
            // Determine slot index (Double-buffered: 2 * W = 64 slots)
            bit<32> slot = (bit<32>)(hdr.switchml.chunk_id % 64);

            // Read state
            bit<32> exp_chunk = 0;
            expected_chunk_id.read(exp_chunk, slot);

            bit<16> current_count = 0;
            count.read(current_count, slot);

            bit<32> current_bitmap = 0;
            bitmap.read(current_bitmap, slot);

            if (hdr.switchml.chunk_id > exp_chunk) {
                // New chunk: overwrite/reset slot
                expected_chunk_id.write(slot, hdr.switchml.chunk_id);
                pool0.write(slot, hdr.switchml.val0);
                pool1.write(slot, hdr.switchml.val1);
                pool2.write(slot, hdr.switchml.val2);
                pool3.write(slot, hdr.switchml.val3);
                pool4.write(slot, hdr.switchml.val4);
                pool5.write(slot, hdr.switchml.val5);

                bit<16> initial_count = 1;
                count.write(slot, initial_count);

                bit<32> initial_bitmap = ((bit<32>)1) << (bit<8>)hdr.switchml.rank;
                bitmap.write(slot, initial_bitmap);

                if (initial_count == (bit<16>)hdr.switchml.num_workers) {
                    // Complete immediately if there is only 1 worker!
                    std.mcast_grp = 1;
                    hdr.eth.srcAddr = 0x0000000000fe;
                    hdr.eth.dstAddr = 0xffffffffffff;
                    hdr.ipv4.srcAddr = 0x0a0000fe;
                    hdr.ipv4.dstAddr = 0xffffffff;
                    hdr.udp.dstPort = 9999;
                    hdr.udp.srcPort = 0xbee0;
                    hdr.udp.checksum = 0; // Disable UDP checksum
                } else {
                    mark_to_drop(std);
                }
            } else if (hdr.switchml.chunk_id == exp_chunk) {
                // Same chunk
                bit<32> rank_mask = ((bit<32>)1) << (bit<8>)hdr.switchml.rank;
                if ((current_bitmap & rank_mask) == 0) {
                    // Worker hasn't contributed yet
                    int<32> p0 = 0;
                    pool0.read(p0, slot);
                    int<32> new_p0 = p0 + hdr.switchml.val0;
                    pool0.write(slot, new_p0);

                    int<32> p1 = 0;
                    pool1.read(p1, slot);
                    int<32> new_p1 = p1 + hdr.switchml.val1;
                    pool1.write(slot, new_p1);

                    int<32> p2 = 0;
                    pool2.read(p2, slot);
                    int<32> new_p2 = p2 + hdr.switchml.val2;
                    pool2.write(slot, new_p2);

                    int<32> p3 = 0;
                    pool3.read(p3, slot);
                    int<32> new_p3 = p3 + hdr.switchml.val3;
                    pool3.write(slot, new_p3);

                    int<32> p4 = 0;
                    pool4.read(p4, slot);
                    int<32> new_p4 = p4 + hdr.switchml.val4;
                    pool4.write(slot, new_p4);

                    int<32> p5 = 0;
                    pool5.read(p5, slot);
                    int<32> new_p5 = p5 + hdr.switchml.val5;
                    pool5.write(slot, new_p5);

                    bit<32> new_bitmap = current_bitmap | rank_mask;
                    bitmap.write(slot, new_bitmap);

                    bit<16> new_count = current_count + 1;
                    count.write(slot, new_count);

                    if (new_count == (bit<16>)hdr.switchml.num_workers) {
                        // Complete!
                        hdr.switchml.val0 = new_p0;
                        hdr.switchml.val1 = new_p1;
                        hdr.switchml.val2 = new_p2;
                        hdr.switchml.val3 = new_p3;
                        hdr.switchml.val4 = new_p4;
                        hdr.switchml.val5 = new_p5;

                        // Broadcast result to all workers
                        std.mcast_grp = 1;
                        hdr.eth.srcAddr = 0x0000000000fe;
                        hdr.eth.dstAddr = 0xffffffffffff;
                        hdr.ipv4.srcAddr = 0x0a0000fe;
                        hdr.ipv4.dstAddr = 0xffffffff;
                        hdr.udp.dstPort = 9999;
                        hdr.udp.srcPort = 0xbee0;
                        hdr.udp.checksum = 0;
                    } else {
                        mark_to_drop(std);
                    }
                } else {
                    // Worker has already contributed to this active chunk
                    if (current_count == (bit<16>)hdr.switchml.num_workers) {
                        // The aggregation is already complete!
                        // This must be a retransmission request from a worker that missed the broadcast.
                        // Resend the completed result from the pools via UNICAST.
                        int<32> p0 = 0;
                        pool0.read(p0, slot);
                        hdr.switchml.val0 = p0;

                        int<32> p1 = 0;
                        pool1.read(p1, slot);
                        hdr.switchml.val1 = p1;

                        int<32> p2 = 0;
                        pool2.read(p2, slot);
                        hdr.switchml.val2 = p2;

                        int<32> p3 = 0;
                        pool3.read(p3, slot);
                        hdr.switchml.val3 = p3;

                        int<32> p4 = 0;
                        pool4.read(p4, slot);
                        hdr.switchml.val4 = p4;

                        int<32> p5 = 0;
                        pool5.read(p5, slot);
                        hdr.switchml.val5 = p5;

                        // Broadcast result to all workers (robust against loss and avoids unicast ARP issues)
                        std.mcast_grp = 1;
                        hdr.eth.srcAddr = 0x0000000000fe;
                        hdr.eth.dstAddr = 0xffffffffffff;
                        hdr.ipv4.srcAddr = 0x0a0000fe;
                        hdr.ipv4.dstAddr = 0xffffffff;
                        hdr.udp.dstPort = 9999;
                        hdr.udp.srcPort = 0xbee0;
                        hdr.udp.checksum = 0;
                    } else {
                        // Aggregation in progress, duplicate packet from this worker is dropped.
                        mark_to_drop(std);
                    }
                }
            } else {
                // Packet for an old chunk (chunk_id < exp_chunk)
                mark_to_drop(std);
            }
        } else {
            // Normal L2 forwarding
            dmac.apply();
        }
    }
}

control egress(inout headers_t hdr, inout metadata_t meta,
               inout standard_metadata_t std) {
    const bit<32> PKT_INSTANCE_TYPE_REPLICATION = 5;
    apply {
        // Drop packet if it is being sent back out of the ingress port (loopback filtering during flooding/multicast)
        // EXCEPT if it is a valid SwitchML packet!
        if (std.instance_type == PKT_INSTANCE_TYPE_REPLICATION &&
            std.egress_port == std.ingress_port &&
            !hdr.switchml.isValid()) {
            mark_to_drop(std);
        }
    }
}

control deparse(packet_out pkt, in headers_t hdr) {
    apply {
        pkt.emit(hdr.eth);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.switchml);
    }
}

control checksum_verify(inout headers_t hdr, inout metadata_t meta) { apply {  } }

control checksum_compute(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

V1Switch(parse(),checksum_verify(),ingress(),egress(),checksum_compute(),deparse()) main;
