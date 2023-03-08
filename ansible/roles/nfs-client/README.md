nfs-client
=========

Connect to NFS shares.

Requirements
------------

An NFS server should be configured. Use the `nfs-server` role to configure this on one of your hosts. Probably should be configured on homebase

Role Variables
--------------

List of shares to mount, the `directories` variable should probably contain the same directories as what the `nfs-server` has.


Example Playbook
----------------

```yml
- hosts: proxies
  roles:
     - { role: nfs-client, vars { directories: [ '/dropbox', '/goodies' ] } }
```
