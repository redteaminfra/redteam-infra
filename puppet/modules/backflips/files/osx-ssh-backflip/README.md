# SSH Backflip Generator

This script will produce a backflip payload. 
That payload should then be executed as a shell script on a victim MacOS host to setup an SSH backflip.

## Usage

`sudo python3 makebackflipy.py <username> <victim_host> <c2_fqdn/ip> <port> <remote_port> [victim_proxy:port]`

## Arguments

username: Username of the victim you are compromising. Stored locally in `/opt/backflips` on a proxy

victim_host: Hostname of the MacOS host you are compromising. Stored locally in `/opt/backflips` on a proxy

c2_fqdn/ip: The IP address or domain of the edge sketch node the backflip will connect through

port: Port that forwards back to the victim (tcp/22). Use a range of 4000 and upwards. Track this on the `Table for tracking backflips` in an engagements infra.

remote_port: The secondary edge port that the backflip SSH service is running on, which for RTI is 2222.

victim_proxy:port: If your victim is on a network where a proxy is needed to talk to the internet you should supply it here.

## Clean Up
To remove the backflip on the host mac
`run python3 cleanup.py <payload_name>`
