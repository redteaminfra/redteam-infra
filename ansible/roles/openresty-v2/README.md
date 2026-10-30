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

This should be ran alongside backflips_v2 which are also dockerized SSH backflips to avoid SSH keyfingerprinting.

### `provision.sh`

`provision.sh` is a full deployment orchestration template for a new engagement. It performs the following sequence:

1. Initializes and applies the OCI Terraform configuration using `variables.tfvars`.
2. Runs the OCI Ansible `site.yml` playbook to configure the provisioned OCI resources.
3. Initializes and applies the Sketch Terraform configuration using its `variables.tfvars`.
4. Runs the Sketch Ansible playbook, supplying the SSH public key and SSH config paths.
5. Runs `openresty-proxy-pb.yml` to configure the OpenResty proxy tier (and any other roles included in that playbook, such as `backflips_v2`).

Before running it, replace the placeholder paths in the script with the locations of the OCI Terraform directory, Sketch Terraform directory, Ansible playbooks, SSH public key, and SSH config for the engagement. Confirm that the referenced inventories, playbooks, and `variables.tfvars` files contain the intended hosts and settings. Run it only after completing those substitutions.

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
