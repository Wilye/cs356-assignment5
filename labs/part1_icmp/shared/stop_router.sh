#!/bin/bash
pids=($(ps -e | grep '?' | awk '{print $1}'))

# Iterate over the array of PIDs
for pid in "${pids[@]}"
do
    if [[ "$pid" != "PID" ]]; then
	    echo "Kill PID: $pid"
	    kill -9 $pid
    fi
done
