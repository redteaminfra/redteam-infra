proxypass-setup
=========

This will automatically setup the proxy pass protocols on the ports specified within the playbook from all edge nodes to middles and middles to proxies.

Requirements
------------

The naming convention for your edge nodes is based on what region you deploy them to in your `variables.tfvars` file.

Standard naming convention for edges: `edge-engagement-name-region-0X`

Standard naming convention for middles: `middle0X-engagement-name`

## Step 1
Collect the Proxy IPs from the OCI/AWS terraform output which we will use to populate the nexthop variable within the playbook. 

## Step 2
Collect the Middle IPs from the Sketch terraform output which we will use to populate the nexthop variable within the playbook. 

## Step 3
Determine which ports you would like to use. The original and recommended are port 80, 443, and 2222.


Example Playbook
----------------
Add the following to your `sketch-playbook.yml` based on the number of middle and edge nodes you have created. There should be an entry for each one.

```
- hosts: edge-engagement-name-region-0X
  become: yes
  roles:
    - proxypass-setup
  vars:
    next_hop: 7.7.7.7
    proxy_ports: ["80", "443", "2222"]

- hosts: middle0X-engagement-name
  become: yes
  roles:
    - proxypass-setup
  vars:
    next_hop: 7.7.7.8
    proxy_ports: ["80", "443", "2222"]
```

