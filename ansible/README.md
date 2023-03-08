Host Configuration
==================

Hosts are configured with [Ansible](https://docs.ansible.com/ansible/latest/index.html). 

Most of the host configuration is determined with roles under the `roles` directory. There are two exceptions. At the end of a playbook run hosts are rebooted with `playbooks/reboot.yml` and users are populated with `users/users.yml`

> **Note**: I've noticed that for best result wait 60 seconds after terraform completes before running Ansible.

Running
-------

You can run this playbook with:

```commandline
ansible-playbook -i inventory.ini site.yml
```

If you setup infrastructure with `external/oci` terraform then you already have defined `inventory.ini`. If not you will need to configure your inventory file. See `inventory.ini.example`.

> **Note**: the order of the inventory is specific as to reboot hosts faster. Homebase is the jump host to all subsequent infrastructure, because of this it should be rebooted first.

You will also need a `users/users.yml` file. You can generate this with using [redteam-ssh](https://github.com/redteaminfra/redteam-ssh), or populate it by hand.


Configuration
-------------

- `site.yml` is used to configure all hosts. It includes other playbooks.
  - `homebase.yml` is used for homebase specific role inclusion.
  - `proxies.yml` is used for proxy specific role inclusion.
  - `elk.yml` is used for elk specific role inclusion.

Roles
-----

A number of rules are included in this repository under the `roles` directory. You may also include roles from Ansible Galaxy or any other sources. `.ansible.cfg` is configured to place roles and collections into the `ansible/roles` or `ansible/collections` directories respectively.

Each role that comes with this repository contains a `README.md` that describes the role and how to use it.

There is also a `template` role that can be used to generate a new role with the most commonly used options using the `ansible-galaxy` command from the role directory:

```commandline
ansible-galaxy init --role-skeleton template NEWROLE
```

group_vars
----------
You may configure host group specific variables using the `group_vars/X.yml` files where `X.yml` corresponds to the inventory group `homebase`, `proxies`, `elk`.
