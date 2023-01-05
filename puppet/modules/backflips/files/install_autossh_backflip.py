#!/usr/bin/env python3
# Copyright (c) 2022, Oracle and/or its affiliates.

import sys
import os
import subprocess
import socket

TEMPLATE = """[Unit]
Description=ssh backflip to %(port)d
After=network.target auditd.service

[Service]
ExecStart=/usr/bin/autossh -M0 -oServerAliveInterval=30 -oServerAliveCountMax=5 -oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no -oBatchMode=yes -n -N -R 3004:192.168.0.10:3004 -D :%(proxyport)d -i %(key)s -p%(port)d %(user)s@localhost

[Install]
WantedBy=multi-user.target
"""

def usage():
    sys.stderr.write("install_autossh_backflip.py PORT PROXYPORT KEY\n\n")
    sys.stderr.write("\tPORT is port of backflip reverse listener\n")
    sys.stderr.write("\tPROXYPORT is the port for the SOCKS server to listen on\n")
    sys.stderr.write("\tKEY is the path to the key for the backflip\n")

def run(cmd):
    proc = subprocess.Popen(cmd, shell=True)
    proc.wait()
    if proc.returncode != 0:
        return False
    return True

def check_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', port))
    if result == 0:
        return True
    else:
        return False

def install_service_file(user, path, port, proxyport, key):
    path = "/etc/systemd/system/backflip-%d-%d.service" % (port, proxyport)
    contents = TEMPLATE % {
        'port' : port,
        'proxyport' : proxyport,
        'key' : key,
        'user' : user
    }
    print("contents:\n",  contents)
    with open(path, "w") as f:
        f.write(contents)
    run("systemctl daemon-reload")

def start_and_enable(service_path):
    path = os.path.basename(service_path)
    if not run("systemctl start %s" % path):
        sys.exit(1)
    run("systemctl enable %s" % path)

def main():
    if len(sys.argv) < 4:
        usage()
        sys.exit(1)

    if os.getuid() != 0:
        sys.stderr.write("run as root or with sudo\n")
        sys.exit(1)

    port = int(sys.argv[1])
    proxyport = int(sys.argv[2])
    key = sys.argv[3]

    if not os.path.exists(key):
        sys.stderr.write("cannot access key %s" % key)
        sys.exit(1)

    service_path = "/etc/systemd/system/backflip-%d-%d.service" % (port, proxyport)

    if not check_port(port):
        sys.stderr.write("look like port %d is not open\n" % port)
        sys.exit(1)

    if not os.path.exists(key):
        sys.stderr.write("cannot access key %s" % key)
        sys.exit(1)

    user = os.path.basename(key).split('-')[0]
    install_service_file(user, service_path, port, proxyport, key)
    start_and_enable(service_path)

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
