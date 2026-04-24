#!/bin/bash
echo "Remove source code in the labs directory"
rm labs/part1_icmp/shared/controller.py
rm labs/part2_arp/shared/controller.py
rm labs/part1_icmp/shared/l3_routing.p4
rm labs/part2_arp/shared/l3_routing.p4

echo "Link source code to each lab's shared directory"
ln src/controller.py labs/part1_icmp/shared/controller.py
ln src/controller.py labs/part2_arp/shared/controller.py
ln src/l3_routing.p4 labs/part1_icmp/shared/l3_routing.p4
ln src/l3_routing.p4 labs/part2_arp/shared/l3_routing.p4
