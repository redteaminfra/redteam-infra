ingress-restrictions
=========

This role is used to help reduce the chances for backflip correlation from public ssh keys from tools like Censys.

This will automatically tell middle hosts to only allow connections on port 2222 from edge hosts.

This role only handles the sketch infrastructure as of now.

Requirements
------------

Once you've ran this in your Sketch infrastructure, you will need to grab the IP Addresses or IP Address range from your middles and add them to your OCI/AWS infrastructure manually.

Whenever we do the grand restructure, this should be done automatically for you everywhere.

Example Playbook
----------------

```yml
- hosts: all
  roles:
    - ingress-restrictions
```