common
=========

Common plays to each host
1. update apt and upgrade host
2. install common software
3. write `/etc/hosts`


Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: all
      roles:
         - {{ common }}
