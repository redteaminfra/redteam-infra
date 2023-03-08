unattended-upgrades
=========

Installs unattended-upgrades apt package and configures it when the OS's distribution is Debian.

Requirements
------------

The operating system is Debian based.


Example Playbook
----------------

```yml
- hosts: proxies
  roles:
     - unattended-upgrades
```
