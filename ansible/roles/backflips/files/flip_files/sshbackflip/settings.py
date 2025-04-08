#!/usr/bin/env python3
# Copyright (c) 2024, Oracle and/or its affiliates.

import configparser
import sys
from pathlib import Path

logging = False

# Check for a source of words for the names generator.
if not Path("/usr/share/dict/words").exists():
    sys.stderr.write("'/usr/share/dict/words' not found. You need to install a dictionary with 'apt install wamerican'\n")
    sys.exit(1)

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