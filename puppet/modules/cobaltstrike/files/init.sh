#!/bin/bash

IP=''

if [ -f /sys/hypervisor/uuid ] && [ `head -c 3 /sys/hypervisor/uuid` == ec2 ]; then
    IP=$(hostname -I | tr -d '\n')
else
    IP=$(ip addr | awk '/inet/ && /ens6/{sub(/\/.*$/,"",$2); print $2}')
fi


echo "IP=$IP" > /opt/cobaltstrike/ipenv
echo "PASSWORD=PASSWORD" >> /opt/cobaltstrike/ipenv
