#!/bin/bash
for i in $(seq 1 3);
do
	kathara exec r${i} bash shared/stop_router.sh
done
