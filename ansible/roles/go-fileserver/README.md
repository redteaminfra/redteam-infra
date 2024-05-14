go-fileserver
=========

Installs the go-fileserver from https://github.com/zikwall/go-fileserver

> Simple, Powerful and Productive file server written in Go

An easy way to receive files via http. Recommended to be installed on homebase and sit behind one of the proxy servers.

An example nginx configuration:

```nginx
server {
    listen 443 proxy_protocol ssl;
    server_name example.com;

    ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

    real_ip_header proxy_protocol;

    location /secret/upload {

        if ($request_method = GET) {
            # block get requests to see files uploaded with go-fileserver
            return 404;
        }

        proxy_pass http://homebase:9999;
        # Sets the authorization token so you don't have to
        proxy_set_header Authorization "Bearer Token KYaAfYsNkWTHMRv6vdJv";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

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
