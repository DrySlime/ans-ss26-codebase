#include <core.p4>
#include <v1model.p4>

header ethernet_t {
  bit<48> dstAddr;
  bit<48> srcAddr;
  bit<16> etherType;
}

header calc_t {
  bit<8> op;
  int<32> a;
  int<32> b;
}

struct headers_t {
  ethernet_t eth;
  calc_t calc;
}

struct metadata_t { }

parser parse(packet_in pkt, out headers_t hdr,
             inout metadata_t meta, inout standard_metadata_t std) {
  state start {
    pkt.extract(hdr.eth);
    transition select(hdr.eth.etherType) {
      0x1234: parse_calc;
      default: accept;
    }
  }
  state parse_calc {
    pkt.extract(hdr.calc);
    transition accept;
  }
}

// === IMPORTANT NOTE ===
//
// There is currently a bug with the BMv2 switch P4 compiler
// When reading a signed register, and then using the result for a signed operation,
// the switch actually performs that operation as unsigned instead. This is usually
// fine (e.g. add/sub works fine), but comparissons can fail. This can cause your
// your min/max/shl/shr operations to fail. To avoid it please use the SIGNED macro
// For example:
//
//      int<32> val = -42;
//      signed_register.read(val, 0)
//      if (val < 42) ...         // This will return false
//      if (SIGNED(32,val) < 42) ... // This will return true
//
#define SIGNED(bits,var) ((int<bits>)(bit<bits>)var)

control calculator(inout headers_t hdr, inout metadata_t meta,
                   inout standard_metadata_t std) {

  register<int<32>>(1) mem;

  action add() { hdr.calc.a = hdr.calc.a + hdr.calc.b; }
  action min() {
    if (hdr.calc.a < hdr.calc.b) {
      // a is already min
    } else {
      hdr.calc.a = hdr.calc.b;
    }
  }
  action max() {
    if (hdr.calc.a > hdr.calc.b) {
      // a is already max
    } else {
      hdr.calc.a = hdr.calc.b;
    }
  }
  action neg() { hdr.calc.a = -hdr.calc.a; }
  action shl() { hdr.calc.a = hdr.calc.a << 1; }
  action shr() { hdr.calc.a = hdr.calc.a >> 1; }

  action mstore() {
    int<32> val = 0;
    mem.read(val, 0);
    mem.write(0, hdr.calc.a);
    hdr.calc.a = val;
  }
  action mload() {
    int<32> val = 0;
    mem.read(val, 0);
    hdr.calc.a = val;
  }
  action madd() {
    int<32> val = 0;
    mem.read(val, 0);
    mem.write(0, val + hdr.calc.a);
    hdr.calc.a = val;
  }
  action mmin() {
    int<32> val = 0;
    mem.read(val, 0);
    int<32> old_val = val;
    int<32> new_val = val;
    if (SIGNED(32, val) < hdr.calc.a) {
      new_val = val;
    } else {
      new_val = hdr.calc.a;
    }
    mem.write(0, new_val);
    hdr.calc.a = old_val;
  }
  action mmax() {
    int<32> val = 0;
    mem.read(val, 0);
    int<32> old_val = val;
    int<32> new_val = val;
    if (SIGNED(32, val) > hdr.calc.a) {
      new_val = val;
    } else {
      new_val = hdr.calc.a;
    }
    mem.write(0, new_val);
    hdr.calc.a = old_val;
  }
  action mneg() {
    int<32> val = 0;
    mem.read(val, 0);
    mem.write(0, -val);
    hdr.calc.a = val;
  }
  action mshl() {
    int<32> val = 0;
    mem.read(val, 0);
    mem.write(0, val << 1);
    hdr.calc.a = val;
  }
  action mshr() {
    int<32> val = 0;
    mem.read(val, 0);
    mem.write(0, SIGNED(32, val) >> 1);
    hdr.calc.a = val;
  }

  table operation {
    key = {
      hdr.calc.op: exact;
    }
    actions = {
      add;
      min;
      max;
      neg;
      shl;
      shr;
      mstore;
      mload;
      madd;
      mmin;
      mmax;
      mneg;
      mshl;
      mshr;
      NoAction;
    }
    const entries = {
      1  : add();
      2  : min();
      3  : max();
      4  : neg();
      5  : shl();
      6  : shr();
      11 : mstore();
      12 : mload();
      13 : madd();
      14 : mmin();
      15 : mmax();
      16 : mneg();
      17 : mshl();
      18 : mshr();
    }
    default_action = NoAction;
  }

  apply {
    operation.apply();
  }
}

control ingress(inout headers_t hdr, inout metadata_t meta,
                inout standard_metadata_t std) {
  calculator() calc;

  register<bit<16>>(1) flood_mgid;

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
    if (hdr.calc.isValid()) {
      calc.apply(hdr, meta, std);

      // Swap Ethernet source/destination MAC addresses
      bit<48> temp = hdr.eth.dstAddr;
      hdr.eth.dstAddr = hdr.eth.srcAddr;
      hdr.eth.srcAddr = temp;

      // Send packet back to the ingress port
      std.egress_spec = std.ingress_port;
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
        std.egress_port == std.ingress_port) {
      mark_to_drop(std);
    }
  }
}

control deparse(packet_out pkt, in headers_t hdr) {
  apply {
    pkt.emit(hdr.eth);
    pkt.emit(hdr.calc);
  }
}

control no_checksum(inout headers_t hdr, inout metadata_t meta) { apply {  } }

V1Switch(parse(),no_checksum(),ingress(),egress(),no_checksum(),deparse()) main;

