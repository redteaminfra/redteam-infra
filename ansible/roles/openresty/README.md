openresty
=========

Installs Open Resty to proxies, so we can use nginx with Proxy Protocol, as well as all the extendable features Open Resty provides.

Variables
---------

You may specify different `openresty_ports` than the defaults of 80, 443.

Example Playbook
----------------

```yml
- hosts: servers
  roles:
     - {role: openresty, vars: { openresty_ports: [ 80, 443, 8080 ] } }
```
