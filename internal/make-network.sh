#!/bin/bash

if [[ "$EUID" -ne 0 ]]; then
    echo "Sorry, you need to run this as root"
    exit 2
fi

usage() {
    echo "Usage: $0 <name of network>" >&2
    exit 1
}

network_name=""
id=1

if [ $# == 1 ]; then
    network_name="$1"
else
    usage
fi

id=$(od -A n -t d -N 2 /dev/urandom | tr -d ' ')

# Generate a subnet mask between 1 and 255
subnetMask=$( od -A n -t d -N 1 /dev/urandom | tr -d ' ')

echo "Your network will be named: $network_name"
echo "With the virbr ID of $id"

# Do the setup of the files automatically
cp internal-network.xml $network_name.xml

echo -n "$network_name" > network-name
echo -n "$id" > network-id
echo -n "192.168.$subnetMask" > subnet

sed -i "s/Internal-Network/$network_name/g" $network_name.xml
sed -i "s/virbr1/virbr$id/g" $network_name.xml
sed -i "s/192.168.1/192.168.$subnetMask/g" $network_name.xml

virsh net-define --file $network_name.xml
virsh net-start $network_name
virsh net-autostart $network_name
