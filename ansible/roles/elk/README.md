elk
=========

Installs Elasticsearch and Kibana on the ELK instance with a docker-compose file.

Example Playbook
----------------

```yml
- hosts: elk
  roles:
   - { role: elk, vars: { elk_version: 6.8.23 } }
```
