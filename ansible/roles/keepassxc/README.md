keepassxc
=========

Installs KeePassXC and creates a shared database on Homebase.

The Homebase role must run first to create `/engagement`. The role creates:

- `/engagement/keepass.kdbx` (`root:redteam`, mode `0660`)
- `/engagement/keepass.txt` (`root:redteam`, mode `0640`)

The password is generated once at runtime. The role fails if only one of these
files exists to avoid losing access to an existing database.

Example Playbook
----------------

```yml
- hosts: homebase
  roles:
   - keepassxc
```
