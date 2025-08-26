#!/usr/bin/env python3
# Copyright (c) 2024, Oracle and/or its affiliates.

import configparser
import sys
import os
import zipfile
import tarfile
from pathlib import Path
from urllib.request import urlretrieve
import json

logging = False
configPath = "etc/backflips.conf"
containerMapPath = "etc/ip_mapping.json"

# Check for a source of words for the names generator.
if not Path("/usr/share/dict/words").exists():
    sys.stderr.write("'/usr/share/dict/words' not found. You need to install a dictionary with 'apt install wamerican'\n")
    sys.exit(1)

# Check that hostkeys are available
if not Path("etc/ssh/ssh_host_rsa_key").exists():
    sys.stderr.write("Backflip SSH host keys not found. This is normal the first time you run backflip.py. Don't worry, the keys will be automatically generated now.\n")
    os.system(f"ssh-keygen -t rsa -q -C '' -f 'etc/ssh/ssh_host_rsa_key' -N '' && chown flip:flip etc/ssh/ssh_host_rsa_key")
    os.system(f"ssh-keygen -t ed25519 -q -C '' -f 'etc/ssh/ssh_host_ed25519_key' -N '' && chown flip:flip etc/ssh/ssh_host_ed25519_key")

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
AUTHORIZED_KEYS = Path(f"{BACKFLIPS_BASE_DIR}/etc/authorized_keys/authorized_keys")
PAYLOADS_DIR = Path(f"{BACKFLIPS_BASE_DIR}/payloads/")
CLEANERS_DIR = Path(f"{BACKFLIPS_BASE_DIR}/cleanup/")
BACKFLIPS_DB = Path(f"{BACKFLIPS_BASE_DIR}/etc/backflips_db")

# Load the container IP mapping and compare to backflips.conf
if Path(containerMapPath).exists():
    with open (containerMapPath) as ip_mapping:
        if logging: print("Found IP mapping file, SSH Backflips seems to be using multiple containerized C2 fronts")
        containerIPs = json.load(ip_mapping)
        for container in containerIPs:
            if container in config.sections():
                if logging: print(f"Found container: {container} with IP: {containerIPs.get(container)} in the mapping and IP: {config.get(container, 'internalIP')} in the config")
else:
    containerIPs = None
    if logging: print("No IP mapping file found, looks like we're not using containers")

# Check that the backflips directories are setup with rational structure
if not(KEYS_DIR.exists() and PAYLOADS_DIR.exists() and CLEANERS_DIR.exists()):
    print(f"[*] Backflips output directories are not setup, creating it now under '{BACKFLIPS_BASE_DIR}/'...")
    PAYLOADS_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    CLEANERS_DIR.mkdir(parents=True, exist_ok=True)
    AUTHORIZED_KEYS.parent.mkdir(parents=True, exist_ok=True)
    AUTHORIZED_KEYS.touch(exist_ok=True)

if not(BACKFLIPS_DB).exists():
    etc = Path(f"{BACKFLIPS_BASE_DIR}/etc/")
    etc.mkdir(exist_ok=True)
    with open(BACKFLIPS_DB, "w") as db:
        db.write(f"# SSH-Backflips ssh_config\n\nHost *\nControlMaster Auto\nControlPath {etc}/ssh/controlmasters/%r@%h:%p\nControlPersist 666")

if not(BACKFLIPS_DB).exists():
    controlMasters = Path(f"{etc}/ssh/controlmasters/")
    controlMasters.mkdir(exist_ok=True)