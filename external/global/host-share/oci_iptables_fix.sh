#!/bin/bash

PATTERN="REJECT.*reject-with icmp-host-prohibited"
OFFENDING_LINE=$(iptables -L INPUT --line-numbers| grep -E "${PATTERN}")
if [ ! -z "$OFFENDING_LINE" ]; then
	RULENO=$(echo $OFFENDING_LINE | cut "-d " -f 1)
	iptables -D INPUT $RULENO
	iptables -L INPUT
	iptables-save > /etc/iptables/rules.v4
fi
