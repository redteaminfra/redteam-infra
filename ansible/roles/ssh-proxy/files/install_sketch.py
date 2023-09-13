#!/usr/bin/env python3
# Copyright (c) 2023, Oracle and/or its affiliates.


import argparse
import os
import sys
import base64
import io
import gzip
import re
import tempfile
from pathlib import Path

logging = True


def parse_args():
    parser_desc = "A tool facilitate proxying through sketch infrastructure."
    parser = argparse.ArgumentParser(description=parser_desc)

    parser.add_argument(
        dest="key",
        type=str,
        help="The path to the ssh public key you would like to use.",
    )

    return parser.parse_args()


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
    args = parse_args()

    try:
        KEYPATH = Path(args.key).absolute()

        if not KEYPATH.exists():
            raise

    except:
        print(f'[!] "{args.key}" does not exist!\n')
        sys.exit(1)

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
    cmd = "echo %s | base64 -d | gzip -d | sudo python3" % gzbased.decode("ascii")
    print("[+] paste the following into the victim as the user to install the keys to")
    print(cmd)
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(cmd.encode("ascii"))
    print("[+] This is also available to you in the file %s" % f.name)
    print("[*] Once this command is ran on sketch as the user to install the keys to, run install_proxy.py "
          "<proxy_port> <middle_name> <middle_ip> <edge_name> <edge_ip> <user> <key>")


if __name__ == "__main__":
    main()
