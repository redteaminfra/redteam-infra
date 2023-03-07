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

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

```yml
- hosts: servers
  roles:
     - {{ logstash }}
```
