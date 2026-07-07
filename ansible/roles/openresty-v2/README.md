Role Name
=========

Deploying of multiple websites using docker containers to handle certificate leaks. Will automatically create the website, request the SSL certificate, enable HTTPS and redirects from HTTP to HTTPS.

Requirements
------------

Requires having homebase and sketch setup properly. You will need the middle IPs and Proxy IPs.
Requires the docker role.
Requires grabbing latest IP blocks for ProofPoint (aws.conf, leaseweb.conf, m247.conf)

Additions
---------

This should be ran alongside backflips-v2 which are also dockerized SSH backflips to avoid SSH keyfingerprinting.

Example Playbook
----------------

Create a new playbook file and insert below into it while adding as many proxies as setup

```
---
- hosts: proxy01-ENGAGEMENT-PROD
  become: yes
  roles:
    - docker
    - openresty-v2
  vars:
    domain_names:
      - example.com
      - example2.com
    middle_ip: "MIDDLE1_IP"

- hosts: proxy02-ENGAGEMENT-PROD
  become: yes
  roles:
    - docker
    - openresty-v2
  vars:
    domain_names:
      - example3.com
    middle_ip: "MIDDLE2_IP"
```

Then call it using `ansible-playbook -i site.yml THIS_PLAYBOOK.yml`