disable-ipv6
=========

This role is for Sketch specific changes and it does the following:

* Create directory /etc/ip6tables
* Copies and restores ip6tables rules
* Stop, disable, and mask systemd service for local DNS resolver
* Re-set DNS name servers
* Prefer IPv4 address selection for dual-stack DNS answers

The IPv4 address-selection preference helps sketch outbound proxy paths avoid
attempting IPv6 connections when public IPv6 egress is intentionally blocked.


Role Variables
--------------

`dns_servers` is a list of dns servers you would like to have added to `/etc/resolv.conf`. Defaults are:

```
nameserver 1.1.1.1
nameserver 8.8.8.8
```

Example Playbook
----------------

```yml
- hosts: all
  roles:
   - { role: disable-ipv6, vars: { dns_servers: [ '1.1.1.1', '8.8.8.8' ] } }
```
