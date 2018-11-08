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

if [ $# == 1 ]; then
    network_name="$1"
else
    usage
fi

read -p "This script can cause damage to your infra if VMs are still alive in $network_name. Continue? (y/n)?" choice
if [[ ! $choice =~ ^[Yy]$ ]]; then
  echo "Exiting . . . ";
  exit 1
fi

echo "Your network '$network_name' will be destroyed"

checknetwork=$(virsh net-list --all | grep -wq $network_name)

if [[ $? != 0 ]]; then
  echo "$network_name does not exist"
  exit 2
fi

virsh net-undefine --network $network_name
virsh net-destroy $network_name
