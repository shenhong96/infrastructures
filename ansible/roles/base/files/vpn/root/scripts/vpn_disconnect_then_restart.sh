#!/bin/bash
docker exec qbittorrent curl ifconfig.me
if [[ "$?" -ne "0" ]]; then
   bash ~/scripts/update_restart.sh restart
fi