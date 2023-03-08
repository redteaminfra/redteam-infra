dante-server
=========

[Dante](https://www.inet.no/dante/) is a SOCKS5 server running on the proxies. It is configured to listen on port 1080 on the internal network. You can use it for command line tools that don't have explicitly socks support by crafting a proxychains.conf similar to below.

```ini
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5  192.168.2.11 1080
EOF
```

You would then invoke CLI tool as `proxychains <cli tool>` to proxy through the socks server

Example Playbook
----------------


```yml
- hosts: servers
  roles:
   - dante-server
```
