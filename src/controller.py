#!/usr/bin/env python3
import argparse
import os
import sys
import ipaddress
from time import sleep, time, ctime
from datetime import timedelta


import grpc

# Import P4Runtime lib from parent utils dir
import utils.p4runtime_lib.bmv2 as bmv2
import utils.p4runtime_lib.helper as helper
from utils.p4runtime_lib.error_utils import printGrpcError
from utils.p4runtime_lib.switch import ShutdownAllSwitchConnections
from scapy.all import *
from multiprocessing import Process


ENABLED_PORT  = []
MAX_PORT = 4
CONTROLLER_OP_ARP_ENQUEUE = 0x00
CONTROLLER_OP_ARP_DEQUEUE = 0x01
CONTROLLER_OP_RIP = 0x02
CLONE_SESSION_ARP_REQ = 0x05
MAX_RIP_METRIC = 16
RIP_CMD_REQ = 0x01
RIP_CMD_RESPONSE = 0x02
RIP_BROADCAST_TIME = 10


def construct_router_info():
    port_to_ip_mac = {}
    for port in range(MAX_PORT):
        ip_addr_result = os.popen(f'ip addr show eth{port}').read().split("inet ")
        if (ip_addr_result[0] == ''):
            break
        ip = ip_addr_result[1].split("/")[0]
        mac = os.popen(f'ip link show eth{port}').read().split("link/ether ")[1].split(" ")[0]
        print(ip,mac)
        port_to_ip_mac[port+1] = (ip,mac)
        ENABLED_PORT.append(port+1)
    print("Enabled port on the router:", ENABLED_PORT)
    return port_to_ip_mac

# 1. Initalize necessary tables for ICMP and ARP packet handling.
# 2. Initialize static routing table.         
def init_part2(p4info_helper, s1, port_to_ip_mac:dict, routing_info:str):
    replicas = [{'egress_port':port, 'instance': port} for port in ENABLED_PORT]
    clone_session_entry = p4info_helper.buildCloneSessionEntry(
        clone_session_id=CLONE_SESSION_ARP_REQ,
        replicas=replicas
    )
    s1.WritePREEntry(clone_session_entry)
    
    for port, pair in port_to_ip_mac.items():
        ip, mac = pair
        print ("Add router port to ip mapping", port, ip)
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.icmp_ingress_port_ip",
            match_fields={"standard_metadata.ingress_port": port},
            action_name="MyIngress.change_src_ip",
            action_params={"port_ip": ip}
        )
        s1.WriteTableEntry(table_entry)
        
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.is_router_ip",
            match_fields={"hdr.ipv4.dstAddr": ip},
            action_name="NoAction"
        )
        s1.WriteTableEntry(table_entry) 
        
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.arp_check_target",
            match_fields={"hdr.arp.tgtIP": ip},
            action_name="MyIngress.send_ARP_response",
            action_params={"sndMAC": mac}
        )
        s1.WriteTableEntry(table_entry)
        
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyEgress.port_to_ARP_request",
            match_fields={"standard_metadata.egress_port": port},
            action_name="MyEgress.send_ARP_request",
            action_params={"port_ip": ip,
                        "port_mac": mac}
        )
        s1.WriteTableEntry(table_entry)
    
    # Add static routing table
    with open(routing_info, 'r') as f:
        for line in f:
            ip_mac_pair = line.split(',')
            prefix, prefix_len = ip_mac_pair[0].split('/')
            next_hop_ip = ip_mac_pair[1]
            next_hop_mac = ip_mac_pair[2]
            egress_mac = ip_mac_pair[3]
            egress_port = int(ip_mac_pair[4].strip('\n'))

            print ("Add routing table entry", prefix, prefix_len, next_hop_ip)
            prefix_len = int(prefix_len)

            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_route",
                match_fields={"hdr.ipv4.dstAddr": (prefix,prefix_len)},
                action_name="MyIngress.forward_to_next_hop",
                action_params={"next_hop": next_hop_ip}
            )
            s1.WriteTableEntry(table_entry)
                   

# 1. Initalize necessary tables for ICMP message handling.
# 2. Initialize static routing table and ARP table. 
def init_part1(p4info_helper, s1, port_to_ip_mac:dict, routing_info:str):
    
    # Initialize necessary tables for ICMP message handling
    for port, pair in port_to_ip_mac.items():
        ip, mac = pair
        print ("Add router port to ip mapping", port, ip)
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.icmp_ingress_port_ip",
            match_fields={"standard_metadata.ingress_port": port},
            action_name="MyIngress.change_src_ip",
            action_params={"port_ip": ip}
        )
        s1.WriteTableEntry(table_entry)
        
        table_entry = p4info_helper.buildTableEntry(
            table_name="MyIngress.is_router_ip",
            match_fields={"hdr.ipv4.dstAddr": ip},
            action_name="NoAction"
        )
        s1.WriteTableEntry(table_entry) 
    
    # Add static routing table and Arp table
    with open(routing_info, 'r') as f:
        for line in f:
            ip_mac_pair = line.split(',')
            prefix, prefix_len = ip_mac_pair[0].split('/')
            next_hop_ip = ip_mac_pair[1]
            next_hop_mac = ip_mac_pair[2]
            egress_mac = ip_mac_pair[3]
            egress_port = int(ip_mac_pair[4].strip('\n'))

            print ("Add routing table entry", prefix, prefix_len, next_hop_ip)
            prefix_len = int(prefix_len)

            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.ipv4_route",
                match_fields={"hdr.ipv4.dstAddr": (prefix,prefix_len)},
                action_name="MyIngress.forward_to_next_hop",
                action_params={"next_hop": next_hop_ip}
            )

            print ("Add ARP table entry", next_hop_ip,next_hop_mac,egress_mac)
            s1.WriteTableEntry(table_entry)
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.arp_table",
                match_fields={"meta.next_hop": next_hop_ip},
                action_name="MyIngress.change_dst_mac",
                action_params={"dst_mac": next_hop_mac}
            )

            print ("Add MAC table entry", next_hop_mac,egress_port)

            s1.WriteTableEntry(table_entry)
            table_entry = p4info_helper.buildTableEntry(
                table_name="MyIngress.dmac_forward",
                match_fields={"hdr.ethernet.dstAddr": next_hop_mac},
                action_name="MyIngress.forward_to_port",
                action_params={"egress_port": egress_port,
                                "egress_mac": egress_mac}
            )
            s1.WriteTableEntry(table_entry)      
    

def main(p4info_file_path, bmv2_file_path, routing_info, adj_info, part):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = helper.P4InfoHelper(p4info_file_path)

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        s1 = bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
        )

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                   bmv2_json_file_path=bmv2_file_path)
        print ("Installed P4 Program using SetForwardingPipelineConfig on %s" % s1.name)
        
        port_to_ip_mac = construct_router_info() 

        if (part == 2):
            print ("Initialization for Part 2")
            init_part2(p4info_helper, s1, port_to_ip_mac, routing_info)
        elif (part == 1):
            print ("Initialization for Part 1")
            init_part1(p4info_helper, s1, port_to_ip_mac, routing_info)
            sleep(5)
            print ("Static table insertion done, exit...")
            ShutdownAllSwitchConnections()
            return 
        else:
            print ("Commend line argument --part should be between 1 and 2")
            raise ValueError
       
        # Packet buffer for the packet waiting for an ARP reply 
        # key: next_hop IP addr in int
        # value: a tuple consists of req sent time, req count, and a packet list.
        pkt_buffer = dict()
        
        while (True):
            msg = s1.ReadfromSwitch()
            if (msg.HasField('packet')):
                op = int.from_bytes(msg.packet.metadata[0].value) 
                if (op == CONTROLLER_OP_ARP_ENQUEUE):
                    # Handle ARP miss
                    print ("Broadcast ARP requests to neighbors")
                    next_hop = int.from_bytes(msg.packet.metadata[1].value)
                    print ("next_hop_ip", str(ipaddress.ip_address(next_hop)))
                    print ("next_hop_ip in int:", next_hop)
                    
                    if (next_hop not in pkt_buffer):
                        # initialize pkt_buffer_entry
                        pkt_buffer[next_hop] = [0.0, 0, []]
                    elif (pkt_buffer[next_hop] == None):
                        # race condition, ARP rule is already installed
                        # but a switch issues arp_enqueue before the installation
                        print ("Send packet to switch")
                        s1.sendPktToSwitch(payload=msg.packet.payload)
                        continue
                    # ARP is not done yet, enqueue the packet.
                    print ("Enqueue packet")
                    pkt_buffer[next_hop][0] = time.time()
                    pkt_buffer[next_hop][1] += 1
                    pkt_list = pkt_buffer[next_hop][2]
                    pkt_list.append(msg.packet.payload)

                elif (op == CONTROLLER_OP_ARP_DEQUEUE): 
                    # Handle ARP reply
                   
                    # Retrieve ARP information from the source fields in the ARP header

                    # Router port number that the response came in
                    egress_port = int.from_bytes(msg.packet.metadata[1].value)
                    pkt = Ether(msg.packet.payload)
                    next_hop_ip = pkt[ARP].psrc # This is src protocol (IP) address
                    next_hop_mac = pkt[ARP].hwsrc # This is src hw (MAC) address
                    egress_mac = pkt[Ether].dst # The MAC address of the ingress port

                    print ("Receives ARP reply")
                    print ("egress port in int:", egress_port)
                    
                    ### PART2_TODO: Add arp_table and dmac_forward table entries
                    ### using the above information from ARP reply
                    ### Use p4info_helper.buildTableEntry and s1.WriteTableEntry as in A2
                    table_entry = p4info_helper.buildTableEntry(
                        table_name="MyIngress.arp_table",
                        match_fields={"meta.next_hop": next_hop_ip},
                        action_name="MyIngress.change_dst_mac",
                        action_params={"dst_mac": next_hop_mac}
                    )
                    s1.WriteTableEntry(table_entry)

                    table_entry = p4info_helper.buildTableEntry(
                        table_name="MyIngress.dmac_forward",
                        match_fields={"hdr.ethernet.dstAddr": next_hop_mac},
                        action_name="MyIngress.forward_to_port",
                        action_params={"egress_port": egress_port,
                                       "egress_mac": egress_mac}
                    )
                    s1.WriteTableEntry(table_entry)


                    # Dequeue packets waiting for the ARP reply
                    next_hop_int = int(ipaddress.ip_address(next_hop_ip))
                    print ("next hop ip in str ", str(ipaddress.ip_address(next_hop_ip)))
                    print ("next hop ip in int: ", next_hop_int)
                    # check if any packet to next_hop has been enqueued
                    if (next_hop_int in pkt_buffer and pkt_buffer[next_hop_int] is not None):
                        for pkt in pkt_buffer[next_hop_int][2]:
                            s1.sendPktToSwitch(payload=pkt)
                        pkt_buffer[next_hop_int] = None # marked as resolved
                    else:
                        print ("Do nothing. All packets related to the next_hop are already dequeued.")


    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)
    
    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=True)
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=True)
    parser.add_argument('--routing-info', help='Routing info file',
                        type=str, action="store", required=True)
    parser.add_argument('--adj-info', help='Adjacecy info file',
                        type=str, action="store", required=True)
    parser.add_argument('--part', help='Please specify the Part you are trying to test in a number',
                        type=int, action="store", required=True)
    
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    if not os.path.exists(args.routing_info):
        parser.print_help()
        print("\nrouting_info file not found." % args.bmv2_json)
        parser.exit(1)
    
    main(args.p4info, args.bmv2_json, args.routing_info, args.adj_info, args.part)
