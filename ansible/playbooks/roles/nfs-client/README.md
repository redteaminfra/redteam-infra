Role Name
=========

Connect to NFS shares.

Requirements
------------

An NFS server should be configured. Use the `nfs-server` role to configure this on one of your hosts. Probably should be configured on homebase

Role Variables
--------------

List of shares to mount, the `directories` variable should probably contain the same directories as what the `nfs-server` has.

Dependencies
------------

Just an NFS server.

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: servers
      roles:
         - { role: username.rolename, x: 42 }
