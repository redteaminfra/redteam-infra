Role Name
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

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

```yml
- hosts: servers
  roles:
    - { role: sketchopsec, vars: { middles: ['4.2.2.1', '4.2.2.2'], edges: ['4.2.2.3', '4.2.2.4'] } }
```
