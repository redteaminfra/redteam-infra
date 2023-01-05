#!/usr/bin/python3
# Copyright (c) 2022, Oracle and/or its affiliates.

import base64
import os
import sys
import time

def usage():
    print ("usage: %s <payload_name> " % sys.argv[0])
    sys.exit(1)

name = os.path.basename(__file__)
pubkey="PUBLIC_KEY_PLACEHOLDER"
backflippub="BACKFLIP_PUB_PLACEHOLDER"
payloadkeyname="PRIVATE_KEY_PATH_PLACEHOLDER"
flockfilename="FLOCK_NAME_PLACEHOLDER"
lagentname="LAGENT_NAME_PLACEHOLDER"
home = os.path.expanduser('~')




def main():
    decodepub = base64.b64decode(pubkey).decode('utf-8')
    decodeback = base64.b64decode(backflippub).decode('utf-8')
    if len(sys.argv) < 2:
        usage()
    payload = sys.argv[1]
    print("Removing plist")
    os.system(f"launchctl unload '{home}/Library/LaunchAgents/{lagentname}.plist'")
    os.system(f"rm '{home}/Library/LaunchAgents/{lagentname}.plist'")
    time.sleep(1)
    os.system(f"rm '{home}/Library/LaunchAgents/.{flockfilename}.pl'")
    time.sleep(1)

    print("Removing ssh key")
    os.system(f"rm {home}/.ssh/{payloadkeyname}")
    autkeyfile = open(f"{home}/.ssh/authorized_keys","r")
    authkeyout = open(f"{home}/.ssh/authorized_keys.tmp","w")
    for line in autkeyfile:
        authkeyout.write(line.replace(decodepub, ''))
    
    authkeyout.close()
    autkeyfile.close()
    os.system(f"mv {home}/.ssh/authorized_keys.tmp {home}/.ssh/authorized_keys")

    knownhostfile = open(f"{home}/.ssh/known_hosts","r")
    knownhostfiletmp = open(f"{home}/.ssh/known_hosts.tmp","w")
    for line in knownhostfile:
        knownhostfiletmp.write(line.replace(decodeback,''))
    knownhostfile.close()
    knownhostfiletmp.close()

    os.system(f"mv {home}/.ssh/known_hosts.tmp {home}/.ssh/known_hosts ")

    time.sleep(1)
    print(f"Deleting payload {payload}")
    os.system(f"rm {home}/Library/LaunchAgents/{payload}")

    print("Deleting clean up script")
    os.system(f"rm {name}")

if __name__ == "__main__":
    main()