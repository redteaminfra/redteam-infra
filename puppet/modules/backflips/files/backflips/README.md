# WTF

These are backflip scripts used to create ssh backflips.  This allows
for a connection outbound from a unix system to an attack machine that
provides a reverse tunnel back into that machine's ssh server.  It
deployes keys to make this all possible.  This instantiation is for
EC.

# Contents
* implant.py

A script embedded in install_implant.py that daemonizes and makes ssh
connections

* install_implant.py

A script that runs on client that provisions the keys and runs evil.py

* make_backflip.py

A script that runs on the attack machine that gives the cut-n-paste
command to run on victim

* instalL_proxy.py

A script to install and start a socks proxy back to victim
