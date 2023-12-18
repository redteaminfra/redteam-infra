web-check
=========

> Get an insight into the inner-workings of a given website: uncover potential attack vectors, analyse server architecture, view security configurations, and learn what technologies a site is using.

The web-check project can be found via [https://github.com/lissy93/web-check](https://github.com/lissy93/web-check)

Advised to run this on a proxy in the event you want to perform analyzation of your website or DNS record for any potential OPSEC leaks.

Requirements
------------

Docker needs to be installed on the target host. The docker role included in redteam-infra is included to ensure docker is installed.

Dependencies
------------

`docker` role

Example Playbook
----------------

```yml
- hosts: servers
  roles:
   - web-check
```
