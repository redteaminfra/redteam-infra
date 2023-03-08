logstash
=========

Configure logstash for red team infrastructure hosts (homebase, proxiesXX, elk).

Role Variables
--------------

You may change the version of logstash and the version of java being used. Defaults below:

```yml
logstash_repo: 6.x
openjdk_version: 11
```

Example Playbook
----------------

```yml
- hosts: servers
  roles:
     - logstash
```
