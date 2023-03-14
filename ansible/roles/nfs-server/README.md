nfs-server
=========

Installs `nfs-kernel-server` and configures the NFS server

Role Variables
--------------

A `directories` variable may be define (see example) to create directories of your own to share.

Example Playbook
----------------

```yml
- hosts: homebase
  roles:
     - { role: nfs-server, vars { directories: [ '/dropbox', '/goodies' ] } }
```
