#!/bin/bash
status=$(curl -o /dev/null -s -w "%{http_code}\n" https://qbit.ahlooii.com)
if [ "$status" -eq 200 ]; then
    echo "Nginx is up"
else
    echo "Nginx is down, let's restart it."
    docker restart nginx
fi

