opsec
=========

Homebase has a set of `iptables` rules to prevent new outbound connections to <victim.target> DMZ IP space. This is designed to prevent an opsec mistake of running an exploit or scan from homebase. Users should instead use one of the proxy boxes for attack traffic.

The IPs in this module should be all the CIDR ranges your company uses. Consult an ASN record or your companies internal documentation for this information.


Role Variables
--------------




Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

```yml
- hosts: servers
  roles:
  - { role: opesec, vars: { cidrs: [ "172.16.32.0/23", "10.0.0.0/8" ] } }
```