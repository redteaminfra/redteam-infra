nmap
=========

Bootstraps the installation of nmap `7.93` because at the time our instances did not automatically install it.

Role Variables
--------------

A `nmap_version` variable may be define (see example) to install a different version of nmap.

Example Playbook
----------------

```yml
- hosts: proxies
  roles:
     - { role: nmap, vars { nmap_version: "7.93" } }
```
