backflip-setup
=========

Optional role.

This will automatically setup the SSH backflip from all edge nodes to middle.

Best used for when using only one middle sketch.

Requirements
------------

Operators will still be required to create the backflip on Middle to Proxy0X-Engagement manually.

Must be ran after initial Sketch setup as nginx is required to be installed and loaded.

Example Playbook
----------------

Add to the end of sketch-playbook.yml 

```
- name: Configure backflips via roles
  hosts: all
  become: yes
  roles:
    - backflip-setup
```
