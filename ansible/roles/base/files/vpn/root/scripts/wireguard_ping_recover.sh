#!/bin/bash
STATUS=$(ping 10.0.96.1 -c 1 -v -W 1 | grep 'received' | awk '{printf $4}')
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
if [ $STATUS -eq 0 ];then
#  echo "wireguard is down"
  systemctl restart wg-quick@wg0
  echo "restarted WG on $(date)" >> /tmp/wg_reco.txt
  exit 256
else
#  echo "wireguard is up"
  exit 0
fi   
