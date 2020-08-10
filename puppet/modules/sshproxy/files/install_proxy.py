#!/usr/bin/env python

import sys
import os
import subprocess
import socket

TEMPLATE = """[Unit]
Description=ssh forward socks proxy for %(proxyport)d through %(middle)s -> %(edge)s
After=network.target auditd.service

[Service]
ExecStart=/usr/bin/autossh -oServerAliveInterval=30 -oServerAliveCountMax=5 -oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no -oBatchMode=yes -n -N -D 0.0.0.0:%(proxyport)d -i %(key)s %(user)s@%(middle)s -o "ProxyCommand nc -q0 %(edge)s 22"

[Install]
WantedBy=multi-user.target
"""

def usage():
    sys.stderr.write("install_proxy.py Proxyport Middle Edge User Key\n\n")
    sys.stderr.write(
        "\tPROXYPORT is the port for the SOCKS server to listen on\n")
    sys.stderr.write(
        "\tKEY is the path to the key for the proxy to connect into sketch\n")
    sys.stderr.write("\tMIDDLE the IP address of a middle sketch\n")
    sys.stderr.write("\tEDGE is the IP address of an edge sketch\n")
    sys.stderr.write("\tUser is the user we connect through on sketch. If provisioned with RTI, use `sketchssh` as the user.\n")

def run(cmd):
    proc = subprocess.Popen(cmd, shell=True)
    proc.wait()
    if proc.returncode != 0:
        return False
    return True

def check_port(proxyport):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', proxyport))
    if result == 0:
        return True
    else:
        return False

def install_service_file(proxyport, key, middle, edge, user):
    path = "/etc/systemd/system/sshproxy-%d.service" % (proxyport)
    contents = TEMPLATE % {
        'proxyport': proxyport,
        'middle': middle,
        'edge': edge,
        'key': key,
        'user': user
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
    if len(sys.argv) < 5:
        usage()
        sys.exit(1)

    if os.getuid() != 0:
        sys.stderr.write("run as root or with sudo\n")
        sys.exit(1)

    proxyport = int(sys.argv[1])
    key = sys.argv[2]
    middleIP = sys.argv[3]
    edgeIP = sys.argv[4]
    user = sys.argv[5]

    print(sys.argv)

    if not os.path.exists(key):
        sys.stderr.write("cannot access key %s" % key)
        sys.exit(1)

    service_path = "/etc/systemd/system/sshproxy-%d.service" % (proxyport)

    if check_port(proxyport):
        sys.stderr.write("look like port %d is already used\n" % proxyport)
        sys.exit(1)

    if not os.path.exists(key):
        sys.stderr.write("cannot access key %s" % key)
        sys.exit(1)

    install_service_file(proxyport, key, middleIP, edgeIP, user)
    start_and_enable(service_path)

if __name__ == "__main__":
    main()
