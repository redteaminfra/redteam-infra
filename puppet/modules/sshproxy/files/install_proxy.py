#!/usr/bin/env python

import sys
import os
import subprocess
import socket


SSH = """
ServerAliveInterval 30
ServerAliveCountMax 3
Compression yes
Host %(middleName)s
    Hostname %(middleIP)s
    IdentityFile %(key)s
    User %(user)s
Host %(edgeName)s
    Hostname %(edgeIP)s
    DynamicForward 0.0.0.0:%(proxyport)d    
    ProxyJump %(middleName)s
    IdentityFile %(key)s
    User %(user)s
    RequestTTY no
"""

SYSTEMD = """[Unit]
Description=ssh forward socks proxy for %(proxyport)d through %(middle)s -> %(edge)s
After=network.target auditd.service

[Service]
Environment="AUTOSSH_GATETIME=0"
ExecStart=/usr/bin/autossh -M0 -F %(sshconfig)s -N %(edgeName)s

[Install]
WantedBy=multi-user.target
"""


def usage():
    sys.stderr.write(
        "install_proxy.py Proxyport MiddleName MiddleIP EdgeName EdgeIP User Key\n\n")
    sys.stderr.write(
        "\tPROXYPORT is the port for the SOCKS server to listen on\n")
    sys.stderr.write("\MiddleName the name to give a middle sketch\n")
    sys.stderr.write("\MiddleIP is the address IP of a middle sketch\n")
    sys.stderr.write("\EdgeName the name to give a middle sketch\n")
    sys.stderr.write("\EdgeIP is the IP address of an edge sketch\n")
    sys.stderr.write(
        "\tUser is the user we connect through on sketch. If provisioned with RTI, use `sketchssh` as the user.\n")
    sys.stderr.write(
        "\tKEY is the path to the key for the proxy to connect into sketch\n")


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


def install_service_files(proxyport, key, middleName, middleIP, edgeName, edgeIP, user):

    ssh_path = "/opt/sshproxy/config-%d" % (proxyport)
    ssh_contents = SSH % {
        'middleName': middleName,
        'middleIP': middleIP,
        'edgeName': edgeName,
        'edgeIP': edgeIP,
        'proxyport': proxyport,
        'key': key,
        'user': user
    }
    print("ssh config contents:\n",  ssh_contents)

    with open(ssh_path, "w") as f:
        f.write(ssh_contents)

    service_path = "/etc/systemd/system/sshproxy-%d.service" % (proxyport)
    systemd_contents = SYSTEMD % {
        'sshconfig': ssh_path,
        'proxyport': proxyport,
        'middle': middleIP,
        'edge': edgeIP,
        'key': key,
        'user': user
    }
    print("systemd contents:\n",  systemd_contents)

    with open(service_path, "w") as f:
        f.write(systemd_contents)

    run("systemctl daemon-reload")
    start_and_enable(service_path)
    accept_keys(ssh_path, edgeName)


def start_and_enable(service_path):
    path = os.path.basename(service_path)
    if not run("systemctl start %s" % path):
        sys.exit(1)
    run("systemctl enable %s" % path)


def accept_keys(ssh_path, edgeName):
    print("[*] Run this command to accept the SSH keys and bootstrap the ssh tunnel\n")
    print("ssh -F %s %s", % ssh_path, edgeName)


def main():
    if len(sys.argv) < 5:
        usage()
        sys.exit(1)

    if os.getuid() != 0:
        sys.stderr.write("run as root or with sudo\n")
        sys.exit(1)

    proxyport = int(sys.argv[1])
    middleName = sys.argv[2]
    middleIP = sys.argv[3]
    edgeName = sys.argv[4]
    edgeIP = sys.argv[5]
    user = sys.argv[6]
    key = sys.argv[7]

    print(sys.argv)

    if not os.path.exists(key):
        sys.stderr.write("cannot access key %s" % key)
        sys.exit(1)

    if check_port(proxyport):
        sys.stderr.write("look like port %d is already used\n" % proxyport)
        sys.exit(1)

    if not os.path.exists(key):
        sys.stderr.write("cannot access key %s" % key)
        sys.exit(1)

    install_service_files(proxyport, key, middleName,
                          middleIP, edgeName, edgeIP, user)


if __name__ == "__main__":
    main()
