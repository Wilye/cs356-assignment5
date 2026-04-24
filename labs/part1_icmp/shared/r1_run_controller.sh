#!/bin/bash
PART=1
python3 /shared/controller.py \
    --p4info /shared/l3_routing.p4info.txt \
    --bmv2-json /shared/l3_routing.json \
    --routing-info /shared/routing_info/r1_routing_info \
    --adj-info /shared/routing_info/r1_adj_info \
    --part $PART