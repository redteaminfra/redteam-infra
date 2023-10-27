backflips
=========

These are backflip scripts used to create ssh backflips. This allows
for a connection outbound from a compromised unix system to an attack
machine that provides a reverse tunnel back into the attack machine's
ssh server. It deploys keys to make this all possible.

Linux backflips are in `files/flip_files/linux-ssh-backflips`.

OS X backflips are in `files/flip_files/osx-ssh-backflips`.


Example Playbook
----------------


```yml
- hosts: proxies
  roles:
   - backflips
```
