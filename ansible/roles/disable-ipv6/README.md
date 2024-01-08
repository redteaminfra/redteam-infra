disable-ipv6
=========

This role is for Sketch specific changes and it does the following:

* Create directory /etc/ip6tables
* Copies and restores ip6tables rules
* Stop, disable, and mask systemd service for local DNS resolver
* Re-set DNS name servers


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
   - { role: oci, vars: { dns_servers: [ '1.1.1.1', '8.8.8.8' ] } }
```