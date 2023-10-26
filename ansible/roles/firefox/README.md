firefox
=========

Install Firefox from ppa. Also disable snap on ubuntu.

Installs a number of extensions by default:
- uBlock Origin
- Privacy Badger
- Proxy SwitchyOmega

You can read more on Firefox policies here: https://archive.ph/c0FM3

Example Playbook
----------------


```yml
- hosts: servers
  roles:
   - firefox
```
