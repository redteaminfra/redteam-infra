#!/usr/bin/env bash
set -e

# Check if /opt/mythic exists
if [ -d "/opt/mythic" ]; then
    echo "Mythic already installed"
    exit 0
fi

# Get the latest Mythic tag
LATEST=$(curl -s https://api.github.com/repos/its-a-feature/Mythic/releases/latest | grep '"tag_name"' | cut -d ':' -f 2 | tr -d ' ",\n')

# Clone the Mythic repo
git clone https://github.com/its-a-feature/Mythic.git /opt/mythic

mv /tmp/mythic.env /opt/mythic/.env

# Checkout the latest tag
cd /opt/mythic
git checkout $LATEST

# Run make to build mythic-cli
make
