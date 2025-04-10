#!/usr/bin/env python3
# Copyright (c) 2025, Oracle and/or its affiliates.

import configparser
import sys
import os
import zipfile
import tarfile
from pathlib import Path
from urllib.request import urlretrieve

logging = False

# Check for a source of words for the names generator.
if not Path("/usr/share/dict/words").exists():
    sys.stderr.write("'/usr/share/dict/words' not found. You need to install a dictionary with 'apt install wamerican'\n")
    sys.exit(1)

# Check that hostkeys are available
if not Path("etc/ssh/ssh_host_rsa_key").exists():
    sys.stderr.write("Backflip SSH host keys not found, this can happen the first time the server is run. Don't worry, backflip.py will generate new host keys.\n")
    os.system(f"ssh-keygen -t rsa -f etc/ssh/ssh_host_rsa_key && chown flip:flip etc/ssh/ssh_host_rsa_key")
    os.system(f"ssh-keygen -t ed25519 -f etc/ssh/ssh_host_ed25519_key && chown flip:flip etc/ssh/ssh_host_ed25519_key")


# Check for Win32-OpenSSH and Git connect.exe bins necesary for Windows payloads
if not Path("sshbackflip/windows/OpenSSH-Template/ssh.exe").exists():
    sys.stderr.write("'Win32-OpenSSH' not found. This is normal the first time you run backflip.py. It will be downloaded from Github.\n")

    pathOpenSSH = Path("sshbackflip/windows/OpenSSH-Template/")
    pathOpenSSH.mkdir(parents=True, exist_ok=True)
    print("Downloading Win32-OpenSSH")
    tempFile, headers = urlretrieve("https://github.com/PowerShell/Win32-OpenSSH/releases/latest/download/OpenSSH-Win64.zip")
    print("Download complete, extracting")

    with zipfile.ZipFile(tempFile, 'r') as zip_fd:
        zip_fd.extract("OpenSSH-Win64/libcrypto.dll", f"{pathOpenSSH}/libcrypto.dll")
        zip_fd.extract("OpenSSH-Win64/ssh.exe", f"{pathOpenSSH}/ssh.exe")
        zip_fd.extract("OpenSSH-Win64/sshd.exe", f"{pathOpenSSH}/sshd.exe")

# Check for Git connect.exe bin necessayr for Windows payloads
if not Path("sshbackflip/windows/OpenSSH-Template/connect.exe").exists():
    sys.stderr.write("'Git's connect.exe' not found. This is normal the first time you run backflip.py. It will be downloaded from Github.\n")

    pathOpenSSH = Path("sshbackflip/windows/OpenSSH-Template/")
    print("Downloading Git for Windows")
    tempFile, headers = urlretrieve("https://github.com/git-for-windows/git/releases/download/v2.49.0.windows.1/Git-2.49.0-64-bit.tar.bz2")
    print("Download complete, extracting")

    with tarfile.open(tempFile, 'r') as tar_fd:
        tar_fd.extract("mingw64/bin/connect.exe", f"{pathOpenSSH}/connect.exe")

# Load and set global configs
if not Path('etc/backflips.conf').exists():
    print("SSH Backflips configuration file 'backflips.conf' not found. It's required.")
    sys.exit(1)

config = configparser.ConfigParser()
config.read('etc/backflips.conf')
BACKFLIPS_BASE_DIR = Path(config['DEFAULT']['backflipPath'])
BACKFLIP_SERVER = config['DEFAULT']['backflipServer']
BACKFLIP_PORT = config['DEFAULT']['backflipPort']
BACKFLIP_USER = config['DEFAULT']['backflipUser']
KEYS_DIR = Path(f"{BACKFLIPS_BASE_DIR}/keys/")
PAYLOADS_DIR = Path(f"{BACKFLIPS_BASE_DIR}/payloads/")
CLEANERS_DIR = Path(f"{BACKFLIPS_BASE_DIR}/cleanup/")
BACKFLIPS_DB = Path(f"{BACKFLIPS_BASE_DIR}/etc/backflips_db")

# Check that the backflips directories are setup with rational structure
if not(KEYS_DIR.exists() and PAYLOADS_DIR.exists() and CLEANERS_DIR.exists()):
    print(f"[*] Backflips output directories are not setup, creating it now under '{BACKFLIPS_BASE_DIR}/'...")
    PAYLOADS_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    CLEANERS_DIR.mkdir(parents=True, exist_ok=True)
    #setup etc/

if not(BACKFLIPS_DB).exists():
    etc = Path(f"{BACKFLIPS_BASE_DIR}/etc/")
    etc.mkdir(exist_ok=True)
    with open(BACKFLIPS_DB, "w") as db:
        db.write("# SSH-Backflips ssh_config\n\n")