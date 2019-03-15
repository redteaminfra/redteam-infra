# Red Team Infrastructure Training

## Introduction

Repeatable, Modular, Dynamic, Auditable and Secure infrastructure is now available for Red Team engagements / operations thanks to Mike Leibowitz and Topher Timzen.

https://github.com/redteaminfra/redteam-infra

This training session will bring you up to speed on:

- Architecture
- Moving into the new workspace
- Supported workflows
- Hands on exercises to familiarize yourself

## SSH

Due to the need for more advanced key deployment, the SSH key repo was rearchitected. Use cases now support:

- Tags for core red team

- Ability to change SSH keypairs, usernames, and real names on the fly

- Ease of provision across multiple environments

The repo is public https://github.com/redteaminfra/redteam-ssh

- Documentation available in the README

### New User

1. ssh-keygen –b 4096
1. Git clone https://github.com/redteaminfra/redteam-ssh
1. Cd sshkeys
1. user_tool.py -j users.json add -u '<YOUR USERNAME>' -n '<YOUR NAME>' -k <PATH OF PUBLIC KEY> -t volunteer
1. Git add users.json
1. Git commit –m “Adding <YOUR NAME>”
1. Git push origin master

### Forgotten Key / Adjustments to Keys

Did you forget your ssh keypair or lose your private key? Read the users.json file to find the UID associated with your username.

1. `ssh-keygen –b 4096`
1. Git clone https://github.com/redteaminfra/redteam-ssh
1. Cd sshkeys
1. user_tool.py mod -j <json_file> --uid <uid> [-n <name>] [-u <username>] [-k <PATH OF PUBLIC KEY>] -t volunteer

Adjust as needed depending on what you want to modify. You always use the uid of your user.

### SSH Stanza

When infrastructure is provisioned, an SSH Stanza will be produced that relies on you having a key in this repository. 

SSH usage is the core of how we do our work on the Red Team. 

More on this later . . .

## ARCHITECTURE

Dual hosted in Amazon Web Services (AWS) and Internally 

Designed to be repeatable, modular, dynamic, auditable and secure. 

Key technologies used for the deployment

- Vagrant - Deployment

- Puppet - Provisioning

- AWS Modules such as boto3 – Starting instances, VPCs, Security Groups

- AWS – Hosting Provider

- Libvirt (KVM) – Internal Hosting provider

Logging

- Elastic Stack (All machine ship logs to a centralized server running Kibana)

Proxies

- Allow operational safe C2 channels 

Homebase

- Our new home. Move in and all work occurs here.

- Natlas

Port scanning machine.

### VPC

A VPC, Virtual Private Cloud, is a logically isolated section of AWS Cloud hosting. The network is completely controlled by us and allows us to use private IP spaces inside of our AWS instances. 

Public-facing subnets can be issued to a VPC to allow for external usage of instances. 

A VPC will be defined for each engagement that will prevent cross-contamination between parallel and past engagements to minimize data exposed inside of AWS at a given time. It also provides us the ability to keep the same architecture across each operation. 

Each VPC will contain the internal IP space of 192.168.0.0/16, which we use 192.168.1.0/24.
An internal network topology is setup inside each VPC inside the infra.us domain. Furthermore, each VPC will be prefixed with an engagement name such as BOX-OPERATION.infra.us. 

Important Note: infra.us is internal routing inside the VPC in /etc/hosts

### Homebase

Homebase-[Op Name].infra.us

- 192.168.1.10
- Kali machine with SSH open to victim.target
- This machine is the only one we connect to from victim.target and is used to move between other machines within the VPC. 
- IRC Server hosted on localhost
- Cobalt Strike hosted on localhost

### Proxies

Proxy Machines (proxy[01,02]-[Op Name].infra.us)

- 192.168.1.11, 192.168.1.12
- These machines receive C2 traffic from victim.target and are indictable by blue. The proxies serve two functions, forward and reverse. 
- They reverse proxy incoming connections from victim.target (http/https traffic) to homebase or other C2 servers as need arises.
- The forward proxy forwards attack traffic from homebase or other attack machines back to victim.target 

### Natlas

Natlas (natlas-[Op Name].infra.us)

- 192.168.1.14
- Port scanning machine that hosts Natlas

### Elastic

Elastic Stack (elk-[Op Name].infra.us)

- 192.168.1.13
- Centralized logging server

### Stanza

Plop into ~/.ssh/config

example

```
Host homebase-testing
     HostName <IP>
     User < USERNAME >
     LocalForward 50050 127.0.0.1:50050
     LocalForward 5000 192.168.1.14:80

Host proxy01-testing
     Proxycommand ssh homebase-testing nc -q0 %h.infra.us %p
     User < USERNAME >

Host proxy02-testing
     Proxycommand ssh homebase-testing nc -q0 %h.infra.us %p
     User < USERNAME >

Host natlas-testing
     Proxycommand ssh homebase-testing nc -q0 %h.infra.us %p
     User < USERNAME >
```

### SSH Forwarding within Infra

Only homebase is accessible from victim.target

Connecting to homebase allows access to

- Cobalt Strike on 127.0.0.1:50050
- Natlas on 127.0.0.1:5000
- IRC on Localhost

Cobalt Strike is listening on localhost to prevent OPSEC mistakes (We do not want to end up on Shodan)

### VNC

VNC is available on Homebase which will grant you local access to 

- Cobalt Strike

- Natlas

- Running Kali desktop environment

- Firefox with FoxyProxy

Setting up VNC requires you to find your UID

Find your UID (it is always the same on every system)

```
$ ssh homebase-training id -u
$ ssh homebase-training setup-xfce4-vnc
Forward the ports.  Your port number is (5900 + (UID - 6000) + 1)
$ ssh -L 5901:localhost:5901 homebase-training
$ vncviewer :1
Your vnc
password is your username
```

## OPSEC

In order to maintain operational security, the only inbound connection to our infra is the SSH connection through homebase. 

The proxies will be used for C2 traffic and will be burned by a member of blue. We can always spin up new proxy machines. If we lose homebase, we lost. 

There are rules in place to help prevent OPSEC failures from homebase, not allowing victim.target Ips as outbound in the firewall, but there could be edge cases. Run commands with care and ensure you tunnel through the proxy machines.

Remembering what you did and where you did it is key for continued OPSEC.

## Workflow

As an operator you can attack from homebase through a proxy machine or from a proxy machine directly. Remember, homebase CANNOT touch victim.target directly. 

Example: Running nmap against a victim from AWS will require tunneling through the proxy into a victim machine. 

Proxychains confiurations live in ~/proxy01 & ~/proxy02 after initialization of your user account per VPC

ctimzen@homebase-training:~/proxy01$ proxychains nmap target.victim

### Commands

All commands ran from homebase need to be prefaced with `proxychains` or run on the proxies directly if you want to talk to victim.target

### How to use proxies

Proxies are in ~/proxy01 and ~/proxy02

You must be in the proxy folder to use that machine as a proxy. 

Use ‘proxychains’ for every command you want to run

### IRC

```
Irssi
/server 127.0.0.1
/join #red
/me waves hi

```

### First connect

Anytime you connec to a new homebase you must run `setup-xfce4-vnc`
