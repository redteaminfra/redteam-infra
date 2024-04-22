proxypass-setup
=========

This will automatically setup the proxy pass protocols on port 80, 443 and 2222 from all edge nodes to middles and middles to proxies.

Requirements
------------

The naming convention for your edge nodes is based on what region you deploy them to in your `variables.tfvars` file.

Standard naming convention for edges: `edge-engagement-name-region-0X`

Standard naming convention for middles: `middle0X-engagement-name`

## Step 1
Collect the Proxy IPs from the OCI/AWS terraform output and populate the role variables within the playbook. Ensure the below code snippet is added to the end of your `sketch-playbook.yml` itself as Nginx is required before we can run this role.

```
- name: Deploy proxypass-setup
  hosts: all
  become: yes
  roles:
    - { role: proxypass-setup, vars: { proxies: ['10.0.0.1', '10.0.0.2'] }}
```

## Step 2
Update role's tasks file to manage the mapping between edges <-> middles & middles <-> proxies. This will be located in the `tasks/main.yml`

```
- name: Determine middle node IP for each edge node
  set_fact:
    middle_host_ip: "{{ middle_ips_dict['middle01-engagemet-name'] }}"
  when: "inventory_hostname in ['edge-engagement-name-jp-osa-01']"

- name: Determine middle node IP for each edge node
  set_fact:
    middle_host_ip: "{{ middle_ips_dict['middle02-engagemet-name'] }}"
  when: "inventory_hostname in ['edge-engagemet-name-in-maa-01']"

- name: Determine proxy node IP for each middle node
  set_fact:
    proxy_ip: "{{ proxies[0] }}"
  when: "'middle01' in inventory_hostname"

- name: Determine proxy node IP for each middle node
  set_fact:
    proxy_ip: "{{ proxies[1] }}"
  when: "'middle02' in inventory_hostname"
```


Example Playbook
----------------
Add the following to the end of your `sketch-playbook.yml` as Nginx is required by Middle and Edge nodes before the role can be applied.

```
- name: Deploy proxypass-setup
  hosts: all
  become: yes
  roles:
    - { role: proxypass-setup, vars: { proxies: ['IP1', 'IP2']}}
```

