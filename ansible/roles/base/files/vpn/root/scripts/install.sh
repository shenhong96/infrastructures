#!/bin/bash


if grep -i 'ubuntu' /etc/os-release
then
	PACKAGE_MANAGER=apt
fi

if grep -i 'red hat' /etc/os-release
then
	PACKAGE_MANAGER=yum
fi

if [ -z $1 ]
then
	echo enter name of package you want to install
	read PACKAGE
else
	PACKAGE=$1
fi


echo PACKAGE_MANAGER=$PACKAGE_MANAGER
echo PACKAGE=$PACKAGE


$PACKAGE_MANAGER install $1 -y
