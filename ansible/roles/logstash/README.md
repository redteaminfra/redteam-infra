logstash
=========

Applied to all instances, so they know how to ship logs to the ELK instance.

Logging is being done with an elastic stack running on the elk host. ELK server will have Kibana and Elastic while all other machines in the VPC ship logs to it with logstash.

Contains files that tell instances which files to pipe through logstash.

Role Dependencies
-----------------

While not a requirement to use this role, you will need to have an ELK stack setup to actually collect these logs. This is accomplished by run `elk` on your elk host.

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
