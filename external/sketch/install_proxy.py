#!/usr/bin/env python
# Copyright (c) 2023, Oracle and/or its affiliates.

import os
import subprocess
import sys
import socket

TEMPLATE = """
[Unit]
Description=simpleproxy %(lport)d service

[Service]
ExecStart=/usr/bin/simpleproxy -v -L %(lport)d -R %(proxyip)s:%(rport)d

[Install]
"""


def checksock(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', port))
    if result == 0:
        print("[+] port %d is listening and accepted connection" % port)
    else:
        print("[-] could not connect to port %d" % port)
        sys.exit(1)


def run(arg):
    subprocess.call(arg, shell=True)


def usage():
    sys.stderr.write("usage: install_proxy.py <IP> <LPORT> <RPORT>\n")
    sys.stderr.write("\n")
    sys.stderr.write("\t<IP> ip address of proxy\n")
    sys.stderr.write("\t<LPORT> local port to listen on\n")
    sys.stderr.write("\t<RPORT> remote port on proxy\n")
    sys.stderr.write("\n")
    sys.stderr.write("\tmust be run as root\n")


def main():
    if len(sys.argv) < 4:
        usage()
        sys.exit(1)

    proxyip = sys.argv[1]
    lport = int(sys.argv[2])
    rport = int(sys.argv[2])

    if os.getuid() != 0:
        usage()
        sys.exit(1)

    run("DEBIAN_FRONTEND=noninteractive apt-get -y install simpleproxy")
    run("ufw allow %d" % lport)

    service_name = "simpleproxy-%d.service" % lport
    service_path = os.path.join("/etc/systemd/system", service_name)
    with open(service_path, "w") as f:
        f.write(TEMPLATE % {'lport': lport,
                            'rport': rport,
                            'proxyip': proxyip})
    run("systemctl daemon-reload")
    run("systemctl start %s" % service_name)
    run("systemctl enable %s" % service_name)
    checksock(lport)


if __name__ == "__main__":
    main()
