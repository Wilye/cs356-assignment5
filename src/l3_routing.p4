/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
typedef bit<48> macAddr_t;
typedef bit<32> ipAddr_t;
typedef bit<8> controllerOp_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8> hlen;
    bit<8> plen;
    bit<16> op;
    macAddr_t sndMAC;
    ipAddr_t sndIP;
    macAddr_t tgtMAC;
    ipAddr_t tgtIP;
}

/* a basic ip header without options and pad */
header ipv4_t {
    bit<4> ver;
    bit<4> hlen; /* header length */
    bit<8> tos;
    bit<16> len; /* total length */
    bit<16> id;
    bit<3> flags;
    bit<13> offset;
    bit<8> ttl;
    bit<8> proto;
    bit<16> csum;
    ipAddr_t srcAddr;
    ipAddr_t dstAddr;
}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> csum;
    bit<32> data;
}

header tcp_t {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq;
}

header udp_t {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> csum;
}

/* only for queueing packets that wait for an ARP reply */
@controller_header("packet_in")
header packet_in_header_t {
    controllerOp_t op;
    bit<32> operand1;
}

/* for handling RIP packets from the controller */
@controller_header("packet_out")
header packet_out_header_t {
    bit<32> egress_port;
}

struct metadata {
    @field_list(0)
    ipAddr_t next_hop;
}

struct headers {
    packet_in_header_t packet_in;
    packet_out_header_t packet_out;
    ethernet_t ethernet;
    arp_t arp;
    ipv4_t ipv4;
    icmp_t icmp;
    ipv4_t icmp_ipv4;
    tcp_t tcp;
    udp_t udp;
    icmp_t original_icmp;
}

/*************************************************************************
*********************** M A C R O S  ***********************************
*************************************************************************/
#define ETHER_IPV4 0x0800
#define ETHER_ARP 0x0806
#define ARP_HTYPE_ETHER 0x0001
#define ARP_PTYPE_IPv4 0x0800
#define ARP_OP_REQ 0x0001
#define ARP_OP_REPLY 0x0002
#define IPV4_ICMP 0x01
#define IPV4_TCP 0x06
#define IPV4_UDP 0x11
#define ICMP_TYPE_TIME_EXCEEDED 0x0b
#define ICMP_TYPE_DEST_UNREACHABLE 0x03
#define ICMP_CODE_NET_UNREACHABLE 0x00
#define ICMP_CODE_HOST_UNREACHABLE 0x01
#define ICMP_CODE_PORT_UNREACHABLE 0x03
#define ICMP_TYPE_ECHO 0x08
#define ICMP_TYPE_ECHO_REPLY 0x00
#define UDP_PORT_RIP 520

#define CPU_PORT 255
#define CONTROLLER_ARP_ENQUEUE 0x00
#define CONTROLLER_ARP_DEQUEUE 0x01
#define CONTROLLER_RIP 0x02

#define CLONE_SESSION_ARP_REQ 0x05

const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE = 1;

#define IS_I2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE)

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }
    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHER_IPV4: parse_ipv4;
            ETHER_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.proto) {
            IPV4_ICMP: parse_icmp;
            IPV4_TCP: parse_tcp;
            IPV4_UDP: parse_udp;
            default: accept;
        }
    }
    
    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
    
    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true,
            { hdr.ipv4.ver,
                hdr.ipv4.hlen,
                hdr.ipv4.tos,
                hdr.ipv4.len,
                hdr.ipv4.id,
                hdr.ipv4.flags,
                hdr.ipv4.offset,
                hdr.ipv4.ttl,
                hdr.ipv4.proto,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.csum, 
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /* define actions */
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action forward_to_port(bit<9> egress_port, macAddr_t egress_mac) {
        standard_metadata.egress_spec = egress_port;
        hdr.ethernet.srcAddr = egress_mac;
    }

    action forward_to_cpu(controllerOp_t op, bit<32> operand1) {
        hdr.packet_in.setValid();
        hdr.packet_in.op = op;
        hdr.packet_in.operand1 = operand1;
        standard_metadata.egress_spec = CPU_PORT;
    }
  
    action decrement_ttl() {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action copy_ipv4(in ipv4_t src, inout ipv4_t dst) {
        dst.ver = src.ver;
        dst.hlen = src.hlen;
        dst.tos = src.tos;
        dst.len = src.len;
        dst.id = src.id;
        dst.flags = src.flags;
        dst.offset = src.offset;
        dst.ttl = src.ttl;
        dst.proto = src.proto;
        dst.srcAddr = src.srcAddr;
        dst.dstAddr = src.dstAddr;
    }
    action copy_icmp(in icmp_t src, inout icmp_t dst) {
        dst.type = src.type;
        dst.code = src.code;
        dst.csum = src.csum;
        dst.data = src.data;
    }
   
    action send_ICMP_error(in bit<8> type, in bit<8> code) {
        
        hdr.icmp.setValid();
        hdr.icmp_ipv4.setValid();

        // ICMP header
        hdr.icmp.type = type;
        hdr.icmp.code = code;
        hdr.icmp.csum = 0;
        // ICMP payload
        hdr.icmp.data = 0;
        copy_ipv4(hdr.ipv4, hdr.icmp_ipv4);
        
        // IPv4 header
        hdr.ipv4.ttl = 64;
        hdr.ipv4.proto = IPV4_ICMP;
        hdr.ipv4.len = 56;
        ipAddr_t temp = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = temp;

        // Ethernet header, swap src and dst
        macAddr_t temp_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = temp_mac;
        
        // truncate the packet to 70 bytes
        truncate((bit<32>)70);

        // Set forwarding port to ingress port
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action send_ICMP_echo_reply() {
        /* PART1_TODO: complete action send_ICMP_echo_reply */
        /* This action changes an incoming echo request to an echo reply */

        /* 1. Set ICMP type to ICMP_TYPE_ECHO_REPLY and code to 0 */
        /* 2. Set the TTL field of IPV4 header to 64 */
        /* 3. Swap src and dst IP addresses */
        /* 4. Swap src and dst MAC addresses */
        /* 5. Set egress_spec to the ingress port */
    }

    action forward_to_next_hop(ipAddr_t next_hop){
        meta.next_hop = next_hop;
    }

    action change_dst_mac (macAddr_t dst_mac) {
        hdr.ethernet.dstAddr = dst_mac;
    }

    action change_src_ip(ipAddr_t port_ip) {
        hdr.ipv4.srcAddr = port_ip;
    }

    action swap_arp_ip() {
        ipAddr_t temp;
        temp = hdr.arp.sndIP;
        hdr.arp.sndIP = hdr.arp.tgtIP;
        hdr.arp.tgtIP = temp;
    }

    action send_ARP_response(macAddr_t sndMAC) {
        /* PART2_TODO: Complete action send_ARP_response 
           This action changes an incoming ARP request to an ARP reply 
           Argument sndMAC is the MAC address inquired by the request */
        
        /* 1. Complete an ARP header. ARP header is defined in header arp_t.
              The packet's arp header can be accessed with hdr.arp.
              Set the opcode to ARP_OP_REPLY.
              Change the target MAC to the original ARP packet's sender MAC.
              Then swap the sender IP and target IP of the ARP header */
        /* 2. Complete an Ethernet header.  
              Change the dest MAC to the original packet's src MAC 
              Then set the src MAC to sndMAC */
        /* 3. Set egress_spec to the ingress_port */
    }
    
    action clone_packet() {
        // Clone from ingress to egress pipeline
        clone_preserving_field_list(CloneType.I2E, CLONE_SESSION_ARP_REQ, 0);
    }

    /* define routing table */
    table ipv4_route {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            forward_to_next_hop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

    /* define static ARP table */
    table arp_table {
        key = {
            meta.next_hop: exact;
        }
        actions = {
            change_dst_mac;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

    /* define forwarding table */
    table dmac_forward {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward_to_port;
            drop;
        }
        size = 1024;
        default_action = drop;
    }

   /* Check if the dst IP address is one of the router's IP*/
    table is_router_ip {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            NoAction;
        }
        size = 16;
        default_action = NoAction;
    }

    /* Retrieve the IP associated with the ingress port */
    /* Then set the srcIP to it */
    /* This table will be initialized by the controller skeleton code */
    table icmp_ingress_port_ip {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            change_src_ip;
            NoAction;
        }
        size = 16;
        default_action = NoAction;
    }

    table arp_check_target {
        key = {
            hdr.arp.tgtIP: exact;
        }
        actions = {
            send_ARP_response;
            drop;
        }
        size = 16;
        default_action = drop;
    }
   
    apply {
        /* Check if TTL expires */
        if (hdr.ipv4.ttl == 1) {
            /* PART1_TODO: send ICMP time exceeded message */
            /* 1. Send the ICMP time exceeded msg using action send_ICMP_error */
            /* 2. Set the source IP address to the IP of the ingress port
                  using table icmp_ingerss_port_ip */
        }
        /* Check whether the packet's destination is router */
        else if (is_router_ip.apply().hit) {
            /* PART1_TODO: handle the packet of which destination is the router */
            /* 1. If the packet is an ICMP echo packet, send an ICMP echo reply */
            /* using action send_ICMP_echo_reply (you should complete the action) */
            /* 2. Else if the packet is TCP or UDP packet, */
            /* send an ICMP port unreachable msg using action send_ICMP_error */  
            /* 3. Otherwise, drop the packet */
        }
        /* Check if the packet is an ARP packet*/
        else if (hdr.arp.isValid()) {
            /* handle arp request or reply */
            if ((hdr.arp.htype == ARP_HTYPE_ETHER) && (hdr.arp.ptype == ARP_PTYPE_IPv4)) {
                if (hdr.arp.op == ARP_OP_REQ) {
                    /* Handle ARP request */
                    /* Check if the target IP address is one of the router's IP */
                    /* Upon match, send ARP reply to the sender */
                    /* Otherwise, drop the packet */
                    arp_check_target.apply();
                } else if (hdr.arp.op == ARP_OP_REPLY) {
                    /* Handle ARP reply */
                    /* Send it to the controller */
                    /* Then the controller will update the ARP table */
                    meta.next_hop = hdr.arp.sndIP;
                    forward_to_cpu(CONTROLLER_ARP_DEQUEUE, (bit<32>)standard_metadata.ingress_port);
                } else {
                    /* Not expected, drop the packet */
                    drop();
                }
            } else {
                /* Not expected, drop the packet */
                drop();
            }
        }
        else if (hdr.udp.isValid() && hdr.udp.dport==UDP_PORT_RIP) {
            /* handle RIP packets */
            if (hdr.packet_out.isValid()){
                /* If RIP packets are from the controller, forward it to the specified port */
                standard_metadata.egress_spec = (bit<9>)hdr.packet_out.egress_port;
            }
            else{
                /* If RIP packets are from the switch ports, forward it to the controller */
                forward_to_cpu(CONTROLLER_RIP, (bit<32>)standard_metadata.ingress_port);
            }
        }
        else{
            /* L3 routing */
            if (ipv4_route.apply().hit) {
                if(arp_table.apply().hit) {
                    decrement_ttl();
                    dmac_forward.apply();
                } else {
                    /* ARP table miss! */
                    /* Broadcast the packet using clone_packet */
                    /* which will be changed to the ARP request */
                    /* in control MyEgress*/  
                    clone_packet();
                    /* Send the original packet to the controller */
                    forward_to_cpu(CONTROLLER_ARP_ENQUEUE, meta.next_hop);
                }
            } else {
                /* Routing table miss! */
                /* Send ICMP net unreachable msg to the sender */
                if (hdr.icmp.isValid()) {
                    hdr.original_icmp.setValid();
                    copy_icmp(hdr.icmp, hdr.original_icmp);
                } 
                send_ICMP_error(ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_NET_UNREACHABLE);
                icmp_ingress_port_ip.apply();
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {



    action drop() {
        mark_to_drop(standard_metadata);
    }

    action send_ARP_request(ipAddr_t port_ip, macAddr_t port_mac) {
        hdr.ipv4.setInvalid();
        hdr.icmp.setInvalid();
        hdr.udp.setInvalid();
        hdr.tcp.setInvalid();

        hdr.arp.setValid();
        hdr.arp.htype = ARP_HTYPE_ETHER;
        hdr.arp.ptype = ARP_PTYPE_IPv4;
        hdr.arp.hlen = 0x06;
        hdr.arp.plen = 0x04;
        hdr.arp.op = ARP_OP_REQ;
        hdr.arp.sndMAC = port_mac;
        hdr.arp.sndIP = port_ip;
        hdr.arp.tgtMAC = 0; // unused
        hdr.arp.tgtIP = meta.next_hop;

        hdr.ethernet.srcAddr = port_mac;
        hdr.ethernet.dstAddr = 0xFFFFFFFFFFFF;
        hdr.ethernet.etherType = ETHER_ARP;
    }

    table port_to_ARP_request {
        key = {
            standard_metadata.egress_port: exact;
        }
        actions = {
            send_ARP_request;
            drop;
        }
        size = 4;
        default_action = drop;
    }
        
    table dummy {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            NoAction;
        }
        default_action = NoAction;
        support_timeout = true;
    }

    apply {
        if (IS_I2E_CLONE(standard_metadata)) {
            /* Change the packet to an ARP request */
            if (standard_metadata.egress_port == standard_metadata.ingress_port) {
                drop();
            } else {
                port_to_ARP_request.apply();
            }
        }
        dummy.apply();
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true,
            { hdr.ipv4.ver,
                hdr.ipv4.hlen,
                hdr.ipv4.tos,
                hdr.ipv4.len,
                hdr.ipv4.id,
                hdr.ipv4.flags,
                hdr.ipv4.offset,
                hdr.ipv4.ttl,
                hdr.ipv4.proto,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.csum, 
            HashAlgorithm.csum16);

        update_checksum(hdr.icmp_ipv4.isValid() && hdr.tcp.isValid(),
            { hdr.icmp.type,
                hdr.icmp.code,
                hdr.icmp.data,
                hdr.icmp_ipv4.ver,
                hdr.icmp_ipv4.hlen,
                hdr.icmp_ipv4.tos,
                hdr.icmp_ipv4.len,
                hdr.icmp_ipv4.id,
                hdr.icmp_ipv4.flags,
                hdr.icmp_ipv4.offset,
                hdr.icmp_ipv4.ttl,
                hdr.icmp_ipv4.proto,
                hdr.icmp_ipv4.srcAddr,
                hdr.icmp_ipv4.dstAddr,
                hdr.tcp.sport,
                hdr.tcp.dport,
                hdr.tcp.seq,
            },
            hdr.icmp.csum,
            HashAlgorithm.csum16);

        update_checksum(hdr.icmp_ipv4.isValid() && hdr.udp.isValid(),
            { hdr.icmp.type,
                hdr.icmp.code,
                hdr.icmp.data,
                hdr.icmp_ipv4.ver,
                hdr.icmp_ipv4.hlen,
                hdr.icmp_ipv4.tos,
                hdr.icmp_ipv4.len,
                hdr.icmp_ipv4.id,
                hdr.icmp_ipv4.flags,
                hdr.icmp_ipv4.offset,
                hdr.icmp_ipv4.ttl,
                hdr.icmp_ipv4.proto,
                hdr.icmp_ipv4.srcAddr,
                hdr.icmp_ipv4.dstAddr,
                hdr.udp.sport,
                hdr.udp.dport,
                hdr.udp.len,
                hdr.udp.csum
            },
            hdr.icmp.csum,
            HashAlgorithm.csum16);

        update_checksum(hdr.original_icmp.isValid(),
            { hdr.icmp.type,
                hdr.icmp.code,
                hdr.icmp.data,
                hdr.icmp_ipv4.ver,
                hdr.icmp_ipv4.hlen,
                hdr.icmp_ipv4.tos,
                hdr.icmp_ipv4.len,
                hdr.icmp_ipv4.id,
                hdr.icmp_ipv4.flags,
                hdr.icmp_ipv4.offset,
                hdr.icmp_ipv4.ttl,
                hdr.icmp_ipv4.proto,
                hdr.icmp_ipv4.srcAddr,
                hdr.icmp_ipv4.dstAddr,
                hdr.original_icmp.type,
                hdr.original_icmp.code,
                hdr.original_icmp.csum,
                hdr.original_icmp.data,
            },
            hdr.icmp.csum,
            HashAlgorithm.csum16);

    update_checksum_with_payload(hdr.icmp.type==ICMP_TYPE_ECHO_REPLY,
        { hdr.icmp.type,
            hdr.icmp.code,
            hdr.icmp.data
        },
        hdr.icmp.csum,
        HashAlgorithm.csum16); 
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.icmp_ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.original_icmp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
