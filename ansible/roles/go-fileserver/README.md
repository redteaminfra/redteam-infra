go-fileserver
=========

Installs the go-fileserver from https://github.com/zikwall/go-fileserver

> Simple, Powerful and Productive file server written in Go

Role Variables
--------------

go_fileserver_version: "v0.0.1"
bind_address: "0.0.0.0:9999"
root_directory: "/opt/go-fileserver/files"
token: ""

A token will be generated for you if you do not specify one. 

Version 0.0.1 is the latest release version of the go-fileserver

Example Playbook
----------------

```yml
- hosts: servers
  roles:
   - go-fileserver
  vars:
    token: "your_token_or_exclude_variable_for_random_token"
```
