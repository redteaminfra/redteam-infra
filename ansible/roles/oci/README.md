oci
=========

This role is for OCI specific changes. Currently it does the following:

OCI uses an internal DNS resolver of 169.254.169.254. This role blocks this resolver with `iptables`, disables `systemd-resolved.service` and sets the nameservers in `/etc/resolv.conf`.


Role Variables
--------------

`dns_servers` is a list of dns servers you would like to have added to `/etc/resolv.conf`. Defaults are:

```
nameserver 1.1.1.1
nameserver 8.8.8.8
```

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

```yml
- hosts: servers
  roles:
   - { role: oci, vars: { dns_servers: [ '1.1.1.1', '8.8.8.8' ] } }
```