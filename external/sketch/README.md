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

This script is ran on the zero-trust reflector proxies to configure them. 

You will need to add a SSH public key to this script.

## install_proxy.py

Sets up a simpleproxy redirector and associated systemd service file. 

```
usage: install_proxy.py <IP> <LPORT> <RPORT>

        <IP> ip address of proxy
        <LPORT> local port to listen on
        <RPORT> remote port on proxy

        must be run as root
```

# How to Play

1. On trusted host:
  1. cat provision.sh | base64 -w0 | xclip -i
1. On untrusted host (zero-trust reflector):
  1. echo '\<xpaste\>' | base64 -d | bash
1. On trusted host:
  1. cat install_proxy.py | base64 -w0 | xclip -i
1. On untrusted host (zero-trust reflector):
  1. echo '\<xpaste\>' | base64 -d | sudo python - \<IP of a proxy\> 443 443
  1. echo '\<xpaste\>' | base64 -d | sudo python - \<IP of a proxy\> 80 80


# Ideal Stanza

You should be connecting to the sketchy zero-trust instances in disconnected infra. In the case where you are using a double reflector such as `target <-> sketch 2 <-> sketch 1 <-> proxy##` you could perform the following in an SSH Stanza

```
Host sketch1
    Proxycommand ssh proxy##-redteam nc -q0 <IP of sketch 2> %p
    IdentityFile ~/.ssh/sketchyKey

Host sketch2
    Proxycommand ssh sketch2 nc -q0 <IP of sketch 1> %p
    IdentityFile ~/.ssh/sketchyKey
```

This is best used in cases where you are okay with leaking the IP of sketch 1 from a trusted infra ran proxy, but want to keep the IP of sketch 2 safe.

Whend deploying a double reflector you will want to perform the `How to Play` steps twice for each reflector. For `install_proxy.py` you would point the appropriate IP addresses to reflector through with the above reflector setting.