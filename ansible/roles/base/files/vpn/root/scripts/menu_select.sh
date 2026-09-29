#!/bin/bash


PS3='Enter Your Choice: '
options=("Available Ram" "Available Disk Space" "Who Logged In" "Exit")

trap "echo Exit is not possible with INT" SIGINT
echo $options
sleep 5

select opt in "${options[@]}"
do
    case $opt in
        "Available Ram")
            echo $(free -h | grep Mem: | awk '{print $4}')
            ;;
        "Available Disk Space")
            echo $(df -h | grep loop4 | awk '{print $4}')
            ;;
        "Who Logged In")
            echo $(who -a | awk '{print $1$2}' | sed 's/LOGIN//g')
            ;;
        "Exit")
            break;;
        *)
            echo "invalid option $REPLY";;
    esac
done
