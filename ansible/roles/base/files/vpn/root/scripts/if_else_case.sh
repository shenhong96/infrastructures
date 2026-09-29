#!/bin/bash

#install service

if [ -z $1 ] && [ -z $2 ]
then
	echo "please provide script + action + services as argument"
	exit 1
fi

MEMORY=$(free -m | grep Mem: | awk '{print $4}')
echo ${MEMORY}

if [ $MEMORY -lt 2999 ]
then
	echo "insufficient memory"
	exit 1
fi

echo $1
echo $2

case $1 in
install)
	echo installing software
	apt install $2

	;;

enable)
	echo enabling software
	systemctl enable $2
	
	;;

start)
	echo starting software
	systemctl start $2
	
	;;

esac
#start service#

#enable service

#prompt error if no argument provided

#check 256MB ram avaialable before starting nxt service, if no, if no should stop.