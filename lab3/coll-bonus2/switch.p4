#include <core.p4>
#include <v1model.p4>

#define CHUNK_SIZE 2
#define SIGNED(bits,var) ((int<bits>)(bit<bits>)var)

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
    bit<16> op; // 0: SUM/AVG, 1: MIN, 2: MAX
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

    // Switch roles & topology parameters (configured by controller)
    register<bit<16>>(1) is_spine;        // 0 = ToR (Level 1), 1 = Spine (Level 2)
    register<bit<16>>(1) expected_count;  // Expected contributors (e.g. 2 for ToR, 2 for Spine)
    register<bit<16>>(1) tor_rank;        // Rank assigned to this ToR when sending to Spine (0 or 1)
    register<bit<9>>(1)  spine_port;       // Egress port from ToR to Spine switch

    // SwitchML registers (64 slots)
    register<bit<32>>(64) expected_chunk_id;
    register<bit<16>>(64) count;
    register<bit<32>>(64) bitmap;
    register<bit<16>>(64) is_globally_complete;
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
            bit<32> slot = (bit<32>)(hdr.switchml.chunk_id % 64);

            bit<16> spine_flag = 0;
            is_spine.read(spine_flag, 0);

            bit<16> exp_cnt = 0;
            expected_count.read(exp_cnt, 0);

            bit<16> t_rank = 0;
            tor_rank.read(t_rank, 0);

            bit<9> s_port = 0;
            spine_port.read(s_port, 0);

            bit<32> exp_chunk = 0;
            expected_chunk_id.read(exp_chunk, slot);

            bit<16> current_count = 0;
            count.read(current_count, slot);

            bit<32> current_bitmap = 0;
            bitmap.read(current_bitmap, slot);

            bit<16> glob_comp = 0;
            is_globally_complete.read(glob_comp, slot);

            // Handle downward broadcast from Spine switch on ToR switch
            if (spine_flag == 0 && std.ingress_port == s_port) {
                expected_chunk_id.write(slot, hdr.switchml.chunk_id);
                pool0.write(slot, hdr.switchml.val0);
                pool1.write(slot, hdr.switchml.val1);
                pool2.write(slot, hdr.switchml.val2);
                pool3.write(slot, hdr.switchml.val3);
                pool4.write(slot, hdr.switchml.val4);
                pool5.write(slot, hdr.switchml.val5);
                is_globally_complete.write(slot, 1);
                count.write(slot, exp_cnt);

                // Broadcast final result to local workers
                std.mcast_grp = 1;
                hdr.eth.srcAddr = 0x0000000000fe;
                hdr.eth.dstAddr = 0xffffffffffff;
                hdr.ipv4.srcAddr = 0x0a0000fe;
                hdr.ipv4.dstAddr = 0xffffffff;
                hdr.udp.dstPort = 9999;
                hdr.udp.srcPort = 0xbee0;
                hdr.udp.checksum = 0;
            } else {
                if (current_count == 0 || hdr.switchml.chunk_id > exp_chunk) {
                    // New chunk
                    expected_chunk_id.write(slot, hdr.switchml.chunk_id);
                    pool0.write(slot, hdr.switchml.val0);
                    pool1.write(slot, hdr.switchml.val1);
                    pool2.write(slot, hdr.switchml.val2);
                    pool3.write(slot, hdr.switchml.val3);
                    pool4.write(slot, hdr.switchml.val4);
                    pool5.write(slot, hdr.switchml.val5);

                    bit<16> initial_count = 1;
                    count.write(slot, initial_count);
                    is_globally_complete.write(slot, 0);

                    bit<32> initial_bitmap = ((bit<32>)1) << (bit<8>)hdr.switchml.rank;
                    bitmap.write(slot, initial_bitmap);

                    if (initial_count == exp_cnt) {
                        if (spine_flag == 1) {
                            std.mcast_grp = 1;
                            hdr.eth.srcAddr = 0x0000000000fe;
                            hdr.eth.dstAddr = 0xffffffffffff;
                            hdr.ipv4.srcAddr = 0x0a0000fe;
                            hdr.ipv4.dstAddr = 0xffffffff;
                            hdr.udp.dstPort = 9999;
                            hdr.udp.srcPort = 0xbee0;
                            hdr.udp.checksum = 0;
                        } else {
                            hdr.switchml.rank = t_rank;
                            hdr.switchml.num_workers = 2;
                            std.egress_spec = s_port;
                        }
                    } else {
                        mark_to_drop(std);
                    }
                } else if (hdr.switchml.chunk_id == exp_chunk) {
                    bit<32> rank_mask = ((bit<32>)1) << (bit<8>)hdr.switchml.rank;
                    if ((current_bitmap & rank_mask) == 0) {
                        int<32> p0 = 0; pool0.read(p0, slot);
                        int<32> new_p0 = 0;
                        if (hdr.switchml.op == 1) { new_p0 = (hdr.switchml.val0 < SIGNED(32, p0)) ? hdr.switchml.val0 : p0; }
                        else if (hdr.switchml.op == 2) { new_p0 = (hdr.switchml.val0 > SIGNED(32, p0)) ? hdr.switchml.val0 : p0; }
                        else { new_p0 = p0 + hdr.switchml.val0; }
                        pool0.write(slot, new_p0);

                        int<32> p1 = 0; pool1.read(p1, slot);
                        int<32> new_p1 = 0;
                        if (hdr.switchml.op == 1) { new_p1 = (hdr.switchml.val1 < SIGNED(32, p1)) ? hdr.switchml.val1 : p1; }
                        else if (hdr.switchml.op == 2) { new_p1 = (hdr.switchml.val1 > SIGNED(32, p1)) ? hdr.switchml.val1 : p1; }
                        else { new_p1 = p1 + hdr.switchml.val1; }
                        pool1.write(slot, new_p1);

                        int<32> p2 = 0; pool2.read(p2, slot);
                        int<32> new_p2 = 0;
                        if (hdr.switchml.op == 1) { new_p2 = (hdr.switchml.val2 < SIGNED(32, p2)) ? hdr.switchml.val2 : p2; }
                        else if (hdr.switchml.op == 2) { new_p2 = (hdr.switchml.val2 > SIGNED(32, p2)) ? hdr.switchml.val2 : p2; }
                        else { new_p2 = p2 + hdr.switchml.val2; }
                        pool2.write(slot, new_p2);

                        int<32> p3 = 0; pool3.read(p3, slot);
                        int<32> new_p3 = 0;
                        if (hdr.switchml.op == 1) { new_p3 = (hdr.switchml.val3 < SIGNED(32, p3)) ? hdr.switchml.val3 : p3; }
                        else if (hdr.switchml.op == 2) { new_p3 = (hdr.switchml.val3 > SIGNED(32, p3)) ? hdr.switchml.val3 : p3; }
                        else { new_p3 = p3 + hdr.switchml.val3; }
                        pool3.write(slot, new_p3);

                        int<32> p4 = 0; pool4.read(p4, slot);
                        int<32> new_p4 = 0;
                        if (hdr.switchml.op == 1) { new_p4 = (hdr.switchml.val4 < SIGNED(32, p4)) ? hdr.switchml.val4 : p4; }
                        else if (hdr.switchml.op == 2) { new_p4 = (hdr.switchml.val4 > SIGNED(32, p4)) ? hdr.switchml.val4 : p4; }
                        else { new_p4 = p4 + hdr.switchml.val4; }
                        pool4.write(slot, new_p4);

                        int<32> p5 = 0; pool5.read(p5, slot);
                        int<32> new_p5 = 0;
                        if (hdr.switchml.op == 1) { new_p5 = (hdr.switchml.val5 < SIGNED(32, p5)) ? hdr.switchml.val5 : p5; }
                        else if (hdr.switchml.op == 2) { new_p5 = (hdr.switchml.val5 > SIGNED(32, p5)) ? hdr.switchml.val5 : p5; }
                        else { new_p5 = p5 + hdr.switchml.val5; }
                        pool5.write(slot, new_p5);

                        bit<32> new_bitmap = current_bitmap | rank_mask;
                        bitmap.write(slot, new_bitmap);

                        bit<16> new_count = current_count + 1;
                        count.write(slot, new_count);

                        if (new_count == exp_cnt) {
                            hdr.switchml.val0 = new_p0;
                            hdr.switchml.val1 = new_p1;
                            hdr.switchml.val2 = new_p2;
                            hdr.switchml.val3 = new_p3;
                            hdr.switchml.val4 = new_p4;
                            hdr.switchml.val5 = new_p5;

                            if (spine_flag == 1) {
                                std.mcast_grp = 1;
                                hdr.eth.srcAddr = 0x0000000000fe;
                                hdr.eth.dstAddr = 0xffffffffffff;
                                hdr.ipv4.srcAddr = 0x0a0000fe;
                                hdr.ipv4.dstAddr = 0xffffffff;
                                hdr.udp.dstPort = 9999;
                                hdr.udp.srcPort = 0xbee0;
                                hdr.udp.checksum = 0;
                            } else {
                                hdr.switchml.rank = t_rank;
                                hdr.switchml.num_workers = 2;
                                std.egress_spec = s_port;
                            }
                        } else {
                            mark_to_drop(std);
                        }
                    } else {
                        if (current_count == exp_cnt) {
                            if (spine_flag == 1) {
                                int<32> p0 = 0; pool0.read(p0, slot); hdr.switchml.val0 = p0;
                                int<32> p1 = 0; pool1.read(p1, slot); hdr.switchml.val1 = p1;
                                int<32> p2 = 0; pool2.read(p2, slot); hdr.switchml.val2 = p2;
                                int<32> p3 = 0; pool3.read(p3, slot); hdr.switchml.val3 = p3;
                                int<32> p4 = 0; pool4.read(p4, slot); hdr.switchml.val4 = p4;
                                int<32> p5 = 0; pool5.read(p5, slot); hdr.switchml.val5 = p5;

                                std.mcast_grp = 1;
                                hdr.eth.srcAddr = 0x0000000000fe;
                                hdr.eth.dstAddr = 0xffffffffffff;
                                hdr.ipv4.srcAddr = 0x0a0000fe;
                                hdr.ipv4.dstAddr = 0xffffffff;
                                hdr.udp.dstPort = 9999;
                                hdr.udp.srcPort = 0xbee0;
                                hdr.udp.checksum = 0;
                            } else {
                                if (glob_comp == 1) {
                                    int<32> p0 = 0; pool0.read(p0, slot); hdr.switchml.val0 = p0;
                                    int<32> p1 = 0; pool1.read(p1, slot); hdr.switchml.val1 = p1;
                                    int<32> p2 = 0; pool2.read(p2, slot); hdr.switchml.val2 = p2;
                                    int<32> p3 = 0; pool3.read(p3, slot); hdr.switchml.val3 = p3;
                                    int<32> p4 = 0; pool4.read(p4, slot); hdr.switchml.val4 = p4;
                                    int<32> p5 = 0; pool5.read(p5, slot); hdr.switchml.val5 = p5;

                                    std.mcast_grp = 1;
                                    hdr.eth.srcAddr = 0x0000000000fe;
                                    hdr.eth.dstAddr = 0xffffffffffff;
                                    hdr.ipv4.srcAddr = 0x0a0000fe;
                                    hdr.ipv4.dstAddr = 0xffffffff;
                                    hdr.udp.dstPort = 9999;
                                    hdr.udp.srcPort = 0xbee0;
                                    hdr.udp.checksum = 0;
                                } else {
                                    int<32> p0 = 0; pool0.read(p0, slot); hdr.switchml.val0 = p0;
                                    int<32> p1 = 0; pool1.read(p1, slot); hdr.switchml.val1 = p1;
                                    int<32> p2 = 0; pool2.read(p2, slot); hdr.switchml.val2 = p2;
                                    int<32> p3 = 0; pool3.read(p3, slot); hdr.switchml.val3 = p3;
                                    int<32> p4 = 0; pool4.read(p4, slot); hdr.switchml.val4 = p4;
                                    int<32> p5 = 0; pool5.read(p5, slot); hdr.switchml.val5 = p5;

                                    hdr.switchml.rank = t_rank;
                                    hdr.switchml.num_workers = 2;
                                    std.egress_spec = s_port;
                                }
                            }
                        } else {
                            mark_to_drop(std);
                        }
                    }
                } else {
                    mark_to_drop(std);
                }
            }
        } else {
            dmac.apply();
        }
    }
}

control egress(inout headers_t hdr, inout metadata_t meta,
               inout standard_metadata_t std) {
    const bit<32> PKT_INSTANCE_TYPE_REPLICATION = 5;
    apply {
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
