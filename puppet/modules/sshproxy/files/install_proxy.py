#!/usr/bin/env python3
import ipaddress
import sys
import os
import subprocess
import socket
import argparse
from pathlib import Path


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
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
"""


def parse_args():
    desc = 'This script is used to create forward SSH proxies through sketch infrastructure.'
    parser = argparse.ArgumentParser(description=desc)

    parser.add_argument(
        dest="proxy_port",
        type=int,
        help="the port for the SOCKS server to listen on.",
    )
    parser.add_argument(
        dest="middle_name",
        type=str,
        help="the name to give a middle sketch."
    )
    parser.add_argument(
        dest="middle_ip",
        type=str,
        help="the address IP of a middle sketch."
    )
    parser.add_argument(
        dest="edge_name",
        type=str,
        help="the name to give a middle sketch."
    )
    parser.add_argument(
        dest="edge_ip",
        type=str,
        help="the IP address of an edge sketch."
    )
    parser.add_argument(
        dest="user",
        type=str,
        help="the user we connect through on sketch. If provisioned with RTI, use \"sketchssh\" as the user."
    )
    parser.add_argument(
        dest="key",
        type=str,
        help="the path to the key for the proxy to connect into sketch."
    )

    return parser.parse_args()


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
        'edgeName': edgeName
    }
    print("systemd contents:\n",  systemd_contents)

    with open(service_path, "w") as f:
        f.write(systemd_contents)

    run("systemctl daemon-reload")
    start_and_enable(service_path)
    accept_keys(ssh_path, edgeName, proxyport)


def start_and_enable(service_path):
    path = os.path.basename(service_path)
    run("systemctl start %s" % path)
    run("systemctl enable %s" % path)


def accept_keys(ssh_path, edgeName, proxyport):
    print("[*] Run these commands to accept the SSH keys and bootstrap the ssh tunnel\n")
    print("sudo ssh -F %s %s\n" % (ssh_path, edgeName))
    print("sudo systemctl restart sshproxy-%d.service" % proxyport)


def main():

    args = parse_args()

    if os.getuid() != 0:
        sys.stderr.write("run as root or with sudo\n")
        sys.exit(1)

    proxyport = args.proxy_port
    middleName = args.middle_name
    middleIP = args.middle_ip
    edgeName = args.edge_name
    edgeIP = args.edge_ip
    user = args.user
    key = Path(Path(args.key).expanduser().absolute())

    print(f'{sys.argv[0]} {proxyport} {middleName} {middleIP} {edgeName} {edgeIP} {user} {key}')

    # validate addresses look like address
    try:
        ipaddress.ip_address(middleIP)
        ipaddress.ip_address(edgeIP)
    except ValueError as e:
        print(e)
        sys.exit(1)

    if not key.exists():
        sys.stderr.write(f'{key} does not exists.')
        sys.exit(1)

    with open(key) as fd:
        if 'PRIVATE KEY' not in fd.readline():
            sys.stderr.write("exiting, file doesn't appear to be a private key.")
            sys.exit(1)

    if check_port(proxyport):
        sys.stderr.write("look like port %d is already used\n" % proxyport)
        sys.exit(1)

    install_service_files(proxyport, key, middleName,
                          middleIP, edgeName, edgeIP, user)


if __name__ == "__main__":
    main()
