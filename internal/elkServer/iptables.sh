#!/bin/bash

echo "1" > /proc/sys/net/ipv4/ip_forward
echo "1" > /proc/sys/net/ipv4/conf/ens6/forwarding
echo "1" > /proc/sys/net/ipv4/conf/ens5/forwarding

# Flush IPTables
iptables -F
iptables -t nat -F
iptables -X

internalIP=$(/sbin/ifconfig ens6 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}' | tr -d '\n')
externalIP=$(/sbin/ifconfig ens5 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}' | tr -d '\n')

# Forward from vagrant mgmt interface to subnet interface
iptables -t nat -A PREROUTING -p tcp --dport 9200 -j DNAT --to-destination $internalIP:9200
iptables -t nat -A POSTROUTING -p tcp -d $externalIP --dport 9200 -j SNAT --to-source $internalIP

echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections

apt-get install -y iptables-persistent
