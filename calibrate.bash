#!/bin/bash
datetime=$(date +%Y-%m-%d-%H-%M-%S)
csvfile=$datetime.csv
for PLR in 1e-07 1e-06 1e-05 1e-04 1e-03 1e-02 1e-01; do
	for RTT in 0.1 0.2 0.5 1 2 5 10 20 50 100 200 500; do
		datetime=$(date +%Y-%m-%d-%H-%M-%S)
		pcapfile=$datetime.pcap
		./calibrate -plr $PLR -rtt ${RTT}ms -pcapfile $pcapfile | tee -a $csvfile
	done
done
