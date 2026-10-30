#!/usr/bin/env python3
# Copyright (c) 2026, Oracle and/or its affiliates.

import configparser
import sys
import shutil
import zipfile
import tarfile
from pathlib import Path
from urllib.request import urlretrieve

logging = False
configPath = "etc/backflips.conf"

# Check for a source of words for the names generator.
if not Path("/usr/share/dict/words").exists():
    sys.stderr.write("'/usr/share/dict/words' not found. You need to install a dictionary with 'apt install wamerican'\n")
    sys.exit(1)

def ensure_windows_assets():
    """Download Windows payload binaries only when a Windows payload needs them."""
    path_openssh = Path(__file__).parent / "windows" / "OpenSSH-Template"
    path_openssh.mkdir(parents=True, exist_ok=True)

    if not (path_openssh / "ssh.exe").exists():
        sys.stderr.write("'Win32-OpenSSH' not found. Downloading it for Windows payload generation.\n")
        temp_file, _ = urlretrieve("https://github.com/PowerShell/Win32-OpenSSH/releases/latest/download/OpenSSH-Win64.zip")
        with zipfile.ZipFile(temp_file, "r") as zip_fd:
            for member, destination in {
                "OpenSSH-Win64/libcrypto.dll": "libcrypto.dll",
                "OpenSSH-Win64/ssh.exe": "ssh.exe",
                "OpenSSH-Win64/sshd.exe": "sshd.exe",
            }.items():
                with zip_fd.open(member) as source, open(path_openssh / destination, "wb") as target:
                    shutil.copyfileobj(source, target)

    if not (path_openssh / "connect.exe").exists():
        sys.stderr.write("'Git's connect.exe' not found. Downloading it for Windows payload generation.\n")
        temp_file, _ = urlretrieve("https://github.com/git-for-windows/git/releases/download/v2.49.0.windows.1/Git-2.49.0-64-bit.tar.bz2")
        with tarfile.open(temp_file, "r") as tar_fd:
            source = tar_fd.extractfile("mingw64/bin/connect.exe")
            if source is None:
                raise FileNotFoundError("Could not find mingw64/bin/connect.exe in Git for Windows archive")
            with source, open(path_openssh / "connect.exe", "wb") as target:
                shutil.copyfileobj(source, target)

# Load and set global and default configs
if not Path(configPath).exists():
    print("SSH Backflips configuration file 'backflips.conf' not found. It's required.")
    sys.exit(1)

config = configparser.ConfigParser()
config.read(configPath)
BACKFLIPS_BASE_DIR = Path(config['DEFAULT']['baseDir'])
BACKFLIP_SERVER = config['DEFAULT']['callbackHost']
BACKFLIP_IP = config['DEFAULT']['internalIP']
BACKFLIP_PORT = config['DEFAULT']['callbackPort']
BACKFLIP_USER = config['DEFAULT']['callbackUser']
KEYS_DIR = Path(f"{BACKFLIPS_BASE_DIR}/keys/")
AUTHORIZED_KEYS = Path(f"{BACKFLIPS_BASE_DIR}/etc/authorized_keys")
PAYLOADS_DIR = Path(f"{BACKFLIPS_BASE_DIR}/payloads/")
CLEANERS_DIR = Path(f"{BACKFLIPS_BASE_DIR}/cleanup/")
BACKFLIPS_DB = Path(f"{BACKFLIPS_BASE_DIR}/etc/backflips_db")
CONTAINERS_DIR = BACKFLIPS_BASE_DIR / "containers"
MIDDLE_IP = config.get('DEFAULT', 'middleIP', fallback='')
MIDDLE_USER = config.get('DEFAULT', 'middleUser', fallback='sketchssh')
MIDDLE_KEY_PATH = config.get('DEFAULT', 'middleKeyPath', fallback='/opt/ssh-proxy/keys/sketchkey')

# Check that the backflips directories are setup with rational structure
if not(KEYS_DIR.exists() and PAYLOADS_DIR.exists() and CLEANERS_DIR.exists()):
    print(f"[*] Backflips output directories are not setup, creating it now under '{BACKFLIPS_BASE_DIR}/'...")
    PAYLOADS_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    CLEANERS_DIR.mkdir(parents=True, exist_ok=True)
    AUTHORIZED_KEYS.parent.mkdir(parents=True, exist_ok=True)
    AUTHORIZED_KEYS.touch(mode=0o600, exist_ok=True)

if not(BACKFLIPS_DB).exists():
    etc = Path(f"{BACKFLIPS_BASE_DIR}/etc/")
    etc.mkdir(exist_ok=True)
    with open(BACKFLIPS_DB, "w") as db:
        db.write(f"# SSH-Backflips ssh_config\n\nHost *\nControlMaster Auto\nControlPath {etc}/ssh/controlmasters/%r@%h:%p\nControlPersist 666")

if not(BACKFLIPS_DB).exists():
    controlMasters = Path(f"{etc}/ssh/controlmasters/")
    controlMasters.mkdir(exist_ok=True)
