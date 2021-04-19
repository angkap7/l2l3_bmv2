#include <core.p4>
#include <psa.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_VLAN = 0x8100;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;

typedef bit<12> vlan_id_t;
typedef bit<48> ethernet_addr_t;

header ethernet_h{  
        ethernet_addr_t dstAddr;
        ethernet_addr_t srcAddr;
        bit<16> etherType;
}


header vlan_h{
    bit<3> pri;  // Priority code point
    bit<1> cfi; //drop eligible indicator (dei)
    vlan_id_t vlan_id;
    bit<16> etherType;
}



