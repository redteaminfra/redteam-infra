Etherpad
=========

Stands up a local instance of Etherpad for collaborative note-taking.

Etherpad is on 127.0.0.1:9001 and is locally forwarded with SSH

Dependencies
------------

docker

Example Playbook
----------------

```yml
- hosts: homebase
  roles:
   - etherpad
```
