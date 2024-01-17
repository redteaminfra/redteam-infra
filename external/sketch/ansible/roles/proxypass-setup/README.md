proxypass-setup
=========

Optional role.

This will automatically setup the Proxy Protocol chain from all edge nodes to middle. And middle to proxy

Best used for when using only one middle sketch.

This assumes you are pointing middle to proxy01.

Requirements
------------

Must be ran after initial Sketch setup as nginx is required to be installed and loaded. Make sure you copy below into your playbook

If using OCI replace `REPLACE ME` with the following:

"jq '.resources[] | select(.type == \"oci_core_instance\" and .name == \"proxy\") | .instances[0].attributes.public_ip' ../../oci/terraform.tfstate"

If using AWS replace `REPLACE ME` with the following:

"jq '.resources[] | select(.type == \"aws_instance\" and .name == \"proxy\") | .instances[0].attributes.public_ip' ../../aws/terraform.tfstate"

Example Playbook
----------------

Add to the end of sketch-playbook.yml 

```
- name: Configure Host Groups and Variables
  hosts: all
  tasks:
    - name: Extract Proxy-Engagement Public IP Address
      command: REPLACE ME
      register: jq_output
      delegate_to: localhost
      run_once: true

    - name: Set variable to contain proxy public ip
      set_fact:
        proxy_public_ip: "{{ jq_output.stdout | regex_replace('\"', '') }}"
    
    - name: Set Middle variable with Middle Host
      set_fact:
        middle_host_ip: "{{ ansible_facts['default_ipv4']['address'] }}"
      when: "'middle' in inventory_hostname"

- name: Configure backflips via roles
  hosts: all
  become: yes
  roles:
    - proxypass-setup
```
