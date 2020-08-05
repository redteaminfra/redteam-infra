# WTF

These are scipts used to create forward SSH proxies through sketch infrastructure. This allows for a forward proxy connection through our zero-trust instances, allowing us to mask our IP addresses and perform high fidelity adversary emulation. 

## Components

### Install_sketch.py

Used to grab key material off of a proxy to autogenerate a bash command to run on sketch infra. 

### install_proxy.py

Used to install a systemd unit with autossh through zero-trust infra. This provisions a double-hop through a proxy -> middle-sketch -> edge-sketch.

### Provision_sketch.py

Siphoned up by `install_sketch.py` to give a one liner command to run on sketch infra. 

## How to Setup

1. Run `install_sketch.py` on a proxy and then copy the contents to run on two or more sketch boxes (one middle, and N+1 edges). This will distrubte key material living on a proxy such that the autossh tunnel can be established. 

2. Run `install_proxy.py` on a proxy after key material is placed for the sketch setup wanted. This will create a forward socks port with autossh that can then be used as a SOCKS proxy. 