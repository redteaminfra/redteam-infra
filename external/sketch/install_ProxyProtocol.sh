#!/bin/bash
# Copyright (c) 2023, Oracle and/or its affiliates.

usage () {
    echo "./install_Proxy_Protocol.sh <next hop IP> <edge/middle>"
    echo "Example: ./provision.sh 192.168.1.10 edge"
    echo "  <Next Hop IP> is the next hop. e.g.; middle-sketch or prox01-engagement"
    echo "  <edge/middle> is where the sketch is in the double hop"
    exit 1
}

if [ $(whoami) != "root" ]; then
    echo "you must be root"
    exit 1
fi

if [[ -z $1 ]];
then
    usage
fi

NEXTHOP=$1
NODE=$2

if [[ $NODE != "edge" ]] && [[ $NODE != "middle" ]];
then
    usage
fi

if [[ $NODE == "edge" ]];
then
cat <<EOF >> /etc/nginx/nginx.conf
stream {
    server {
            listen 80;
            proxy_pass $NEXTHOP:80;
            proxy_protocol on;
        }
    server {
            listen 443;
            proxy_pass $NEXTHOP:443;
            proxy_protocol on;
        }
}
EOF
fi

if [[ $NODE == "middle" ]];
then
cat <<EOF >> /etc/nginx/nginx.conf
stream {
    server {
        listen 80;
        proxy_pass $NEXTHOP:80;
    }
    server {
        listen 443;
        proxy_pass $NEXTHOP:443;
    }
}
EOF
fi

# Remove default and restart nginx
rm /etc/nginx/sites-enabled/default
systemctl restart nginx
