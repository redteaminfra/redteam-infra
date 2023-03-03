tinyproxy
=========

Installs [tinyproxy](https://tinyproxy.github.io/) on the proxies.  This is a very simple http proxy that allows 192.168.0.0/16 to use it.  All ports are available for CONNECT, so you can effectively use this as an arbitrary tcp proxy.  Using depends on application, but in general, environment variables will do for most tools:

```
http_proxy=http://192.168.1.11:8888/
https_proxy=$http_proxy
curl http://example.com
```

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

```yml
- hosts: proxies
  roles:
   - tinyproxy
```
