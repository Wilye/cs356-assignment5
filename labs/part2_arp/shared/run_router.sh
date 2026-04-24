#!/bin/bash
simple_switch_grpc -i 1@eth0 -i 2@eth1 -i 3@eth2 --no-p4  -- --grpc-server-addr 127.0.0.1:50051 --cpu-port 255 
