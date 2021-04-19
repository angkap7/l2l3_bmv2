#include <core.p4>
#include <psa.p4>

#define ETHERTYPE_IPV4 = 0x08o
#define ETHERTYPE_VLAN = 0x8100;
const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;

typedef bit<12> vlan_id_t;
typedef bit<48> ethernet_addr_t;

header ethernet_t{  
        ethernet_addr_t dstAddr;
        ethernet_addr_t srcAddr;
        bit<16> etherType;
}

header vlan_tag_t {
    bit<3> pri;  // Priority code point
    bit<1> cfi; //drop eligible indicator (dei)
    vlan_id_t vlan_id;
    bit<16> etherType;
}

header ipv4_t {
    bit<8> ver_ihl;
    bit<8> diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<16> flags_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}


header tcp_t {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_t {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> checksum;
}

header bridged_md_t {
    bit<32> ingress_port;
}

struct headers_t {
    bridged_md_t bridged_meta;
    ethernet_t ethernet;
    vlan_tag_t vlan_tag;
    ipv4_t ipv4;
    tcp_t  tcp;
    udp_t  udp;
}

struct mac_learn_digest_t {
    ethernet_addr_t mac_addr;
    PortId_t        port;
    vlan_id_t       vlan_id;
}

struct metadata {
    bool               send_mac_learn_msg;
    mac_learn_digest_t mac_learn_msg;
    bit<16>            l4_sport;
    bit<16>            l4_dport;
}

parser packet_parser(packet_in packet, out headers_t headers, inout local_metadata_t local_metadata, in psa_ingress_parser_input_metadata_t standard_metadata, in empty_metadata_t resub_meta, in empty_metadata_t recirc_meta) {
    InternetChecksum() ck;
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(headers.ethernet);
        transition select(headers.ethernet.ether_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_VLAN : parse_vlan;
            default: accept;
        }
    }

    state parse_vlan {
        packet.extract(headers.vlan_tag);
        transition select(headers.vlan_tag.eth_type) {
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(headers.ipv4);

        ck.subtract(headers.ipv4.hdr_checksum);
        ck.subtract({/* 16-bit word */ headers.ipv4.ttl, headers.ipv4.protocol });
        headers.ipv4.hdr_checksum = ck.get();

        transition select(headers.ipv4.protocol) {
            PROTO_TCP: parse_tcp;
            PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(headers.tcp);
        local_metadata.l4_sport = headers.tcp.sport;
        local_metadata.l4_dport = headers.tcp.dport;
        transition accept;
    }

    state parse_udp {
        packet.extract(headers.udp);
        local_metadata.l4_sport = headers.udp.sport;
        local_metadata.l4_dport = headers.udp.dport;
        transition accept;
    }
}
