# WTF

A very simple set of provision scripts for zero-trust reflector proxies.

# Moving Parts

## provision.sh

Rediculous bash script that:
* adds user 'user' w/ keys (don't forget to put your key there)
* disables password ssh login
* makes 'user' passwordless sudoer
* enables ufw firewall
* installs unattended-upgrades

## install_proxy.py

Sets up a simpleproxy redirector and associated systemd service file

# How to Play
1. On trusted host:
  1. cat provision.sh | base64 -w0 | xclip -i
1. On untrusted host:
  1. echo '\<xpaste\>' | base64 -d | bash
1. On trusted host:
  1. cat install_proxy.py | base64 -w0 | xclip -i
1. On untrusted host (Your sketchy proxies):
  1. echo '\<xpaste\>' | base64 -d | sudo python - \<IP of a proxy\> 443 443
  1. echo '\<xpaste\>' | base64 -d | sudo python - \<IP of a proxy\> 80 80


# Ideal Stanza

You should be connecting to the linode instances in disconnected infra. In the case where you are using a double reflector such as `target <-> sketch 1 <-> sketch 2 <-> proxy02` you could perform the following in an SSH Stanza

```
Host sketch2
    Proxycommand ssh proxy02-redteam nc -q0 <IP of sketch 2> %p
    IdentityFile ~/.ssh/sketchyKey

Host sketch1
    Proxycommand ssh sketch2 nc -q0 <IP of sketch 1> %p
    IdentityFile ~/.ssh/sketchyKey
```

This is best used in cases where you are okay with leaking the IP of sketch 2 from a trusted proxy, but want to keep the IP of sketch 1 safe.
