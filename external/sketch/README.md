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
1. On untrusted host:
  1. echo '\<xpaste\>' | base64 -d | sudo python - \<IP of a proxy\> 443 443
  1. echo '\<xpaste\>' | base64 -d | sudo python - \<IP of a proxy\> 80 80
