sketch-opsec
=========

Provisions OPSEC firewall rules for sketch instances. Ensures that only the middle sketch boxes can be reached from proxies, and blocks all connections to edges.

Requirements
------------

Any pre-requisites that may not be covered by Ansible itself or the role should be mentioned here. For instance, if the role uses the EC2 module, it may be a good idea to mention in this section that the boto package is required.

Role Variables
--------------

`middles` should contain at least one IP address or CIDR.
`edges` should contain at least one IP address or CIDR.


Example Playbook
----------------

```yml
- hosts: servers
  roles:
    - { role: sketch-opsec, vars: { middles: ['4.2.2.1', '4.2.2.2'], edges: ['4.2.2.3', '4.2.2.4'] } }
```
