# WTF

These are backflip scripts used to create ssh backflips. This allows
for a connection outbound from a compromised unix system to an attack
machine that provides a reverse tunnel back into the attack machine's
ssh server. It deploys keys to make this all possible.

Linux backflips are in linux-ssh-backflips.

OS X backflips are in osx-ssh-backflips.

# Things to Take Note of

* Port numbers for both reverse port forwards and socks proxies will
  need to be managed out of band. Implement a process and use it.
* You are running an additional ssh server that your victims ssh
  to. This can be abused by somebody who has control of the victim
  machine. While shell access is disabled, and only reverse forwarding
  will work, one should be aware of this caveat.

# Components

The structure here is a little confusing at first. Because we don't
want to leave a script file on disk, we give cut-n-paste commands that
are of the form `echo xxx|python`. The cut-n-paste command is
generated from the scripts that are indirectly run. This is important
for the operator to understand what these scripts do on target, but
the the scripts the operator directly uses are `make_backflip.py` and
`install_autossh_backflip.py`

# Socks proxies over backflip

## `install_autossh_backflip.py`

runs on attack machine and installs and starts a socks proxy into victim network.