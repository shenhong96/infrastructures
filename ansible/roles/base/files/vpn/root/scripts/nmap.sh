#!/bin/bash
echo enter IP address of network you want to scan for hosts eg:192.168.0.0
read NETWORK

set -x
hosts=()

while IFS= read -r line; do
	hosts+=( "$line" )
done < <(sudo nmap -sn ${NETWORK}/24 | grep ${NETWORK%.*} | awk '{print $5}' )
set +x

echo press enter to continue
read

for i in "${!hosts[@]}"
do
	echo $i ${hosts[$i]} 
done
