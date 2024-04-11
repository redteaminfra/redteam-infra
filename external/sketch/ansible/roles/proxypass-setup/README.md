proxypass-setup
=========

Optional role.

This will automatically setup the proxy protocols on port 2222 from all edge nodes to middles and middles to proxies.


Requirements
------------

Operators will still be required to collect the Proxy IPs from their OCI/AWS ansible output or hosts and populate the playbook variables.

You will also need to update the role's tasks to point edges to specific middles and middles to specific proxies.

In the role's main tasks file, you will need to update or add/remove depending on how many edges/middles you have. The below example is using 2 edge nodes and 2 middles with 1 proxy.

The naming convention for your edge nodes is based on what region you deploy them to in your `variables.tfvars` file.

Standard naming convention for edges: `edge-engagement-name-region-0X`

Standard naming convention for middles: `middle0X-engagement-name`

```
- name: Determine middle node IP for each edge node
  set_fact:
    middle_host_ip: "{{ middles['middle01-engagemet-name'] }}"
  when: "inventory_hostname in ['edge-engagement-name-jp-osa-01']"

- name: Determine middle node IP for each edge node
  set_fact:
    middle_host_ip: "{{ middles['middle02-engagemet-name'] }}"
  when: "inventory_hostname in ['edge-engagemet-name-in-maa-01']"

- name: Determine proxy node IP for each middle node
  set_fact:
    proxy_ip: "{{ proxies[0] }}"
  when: "'middle01' in inventory_hostname"

- name: Determine proxy node IP for each middle node
  set_fact:
    proxy_ip: "{{ proxies[0] }}"
  when: "'middle02' in inventory_hostname"
```


Example Playbook
----------------

Add the following to the beginning of your playbook under "Gather IPs" section:

```
 - name: Set fact for 'middle' hosts
      set_fact:
        is_middle_host: true
      when: "'middle' in inventory_hostname"

    - name: Gather Middle IPs into a dictionary
      set_fact:
        middle_ips_dict: >-
          {{
            middle_ips_dict | default({}) | combine(
              { item: hostvars[item]['host_ip_address'] }
            )
          }}
      loop: "{{ groups['all'] }}"
      when: hostvars[item]['is_middle_host'] is defined and hostvars[item]['is_middle_host']
      delegate_to: localhost
```

Add the following at the end of your playbook as the edges and middle require nginx before this role can be applied.

```
- name: Deploy proxypass-setup
  hosts: all
  become: yes
  roles:
    - { role: proxypass-setup, vars: { proxies: ['IP1', 'IP2'], middles: "{{ middle_ips_dict }}" }}
```

