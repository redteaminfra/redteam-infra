# AWS

This document will serve as a stepping stone to setup and deploy redteam-infra inside of AWS in a detailed manner.

[How to start](https://github.com/redteaminfra/redteam-infra/tree/master/external/aws#how-to-start) currently solves as a beginning reference, but it is by no means complete or detailed enough to get running quickly.

## Things you need to install

- python3
- python3-venv
- [Version 2.0.1](https://releases.hashicorp.com/vagrant/2.0.1/) (See issue [#2](https://github.com/redteaminfra/redteam-infra/issues/2])

## Keypairs

The first thing you'll need to do is setup IAM in AWS and generate an EC2 keypair.

Our infra works in US-WEST so set your region to that!

To do so, from IAM in AWS make a user and add that user to the group "redteam".

Click on the newly created user and go to the "Security Credentials" tab. See under access and obtain the values for "AWS_KEY" and "AWS_SECRET"

You'll need to generate a PRIVATEKEY.pem file and copy it in to the ~/.aws directory.

To do so, log in to AWS and navigate to EC2. Under Network and Security select 'Key Pairs'. Select 'Create Key Pair' and use your username. It should automatically download a .pem file. Copy this .pem file to your AWS directory and rename (mv) it from your username to 'PRIVATEKEY.pem'

Source your aws setup from `~/.aws/awssetup.sh` and make it look like

```
export AWS_KEY="KEY"
export AWS_SECRET="SECRET"
export AWS_KEYNAME=USERNAME
export AWS_KEYPATH="~/.aws/PRIVATEKEY.pem"
```
From there run `source ~/.aws/awssetup.sh` before doing any deployments.

You also need to setup your AWS credentials in `~/.aws/credentials`

```
[default]
aws_access_key_id = <STUFF>
aws_secret_access_key = <THINGS>
```

Also set `~/.aws/config` to your zone such as

```
[default]
region=us-west-2
```

## Repo Setup

Because vagrant makes a local .vagrant folder to house all information about an instance, we need a copy of that repository for every VPC we need in AWS. On the chance that a change is required for the infrastructure a fork is deal.

We'll just use the open source implementation for this walkthrough, but you'll want to fork it and keep somewhere privately for anything you change during operations.

Ideally you'd do the following

1. git clone https://github.com/redteaminfra/redteam-infra <OPNAME>
1. Make a new repo in RedTeamInfra called <OPNAME>
1. git remote rm origin
1. git remote add origin git@github.com:redteaminfra/<OPNAME>
1. git push origin master

For now, we will just `git clone https://github.com/redteaminfra/redteam-infra redteam-infra-demo`

```
{ tools }  > git clone git@github.com:redteaminfra/redteam-infra.git redteam-infra-demo
Cloning into 'redteam-infra-demo'...
remote: Enumerating objects: 360, done.
remote: Counting objects: 100% (360/360), done.
remote: Compressing objects: 100% (235/235), done.
remote: Total 360 (delta 71), reused 333 (delta 53), pack-reused 0
Receiving objects: 100% (360/360), 520.65 KiB | 4.23 MiB/s, done.
Resolving deltas: 100% (71/71), done.
{ tools }  > cd redteam-infra-demo

```

## SSH Keys and repo

The infra repo makes use of submodules for SSH from [redteam-ssh](https://github.com/redteaminfra/redteam-ssh).

We need to setup a submodule to handle SSH access and add some keys to `users.json`

Assuming this is the first time setting this up, let's go do that.

First, you'll want to fork / put / whatever your solution is the redteam-ssh keys repo somewhere from [here](https://github.com/redteaminfra/redteam-ssh demo-keys).

I just forked it for the examples of this walkthrough.

```
{ tools }  >  git clone https://github.com/tophertimzen/redteam-ssh demo-keys
Cloning into 'demo-keys'...
remote: Enumerating objects: 9, done.
remote: Counting objects: 100% (9/9), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 9 (delta 0), reused 9 (delta 0), pack-reused 0
Unpacking objects: 100% (9/9), done.

{ tools }  > cd demo-keys

{ demo-keys } master > ssh-keygen -b 4096
Generating public/private rsa key pair.
Enter file in which to save the key (/home/demo/.ssh/id_rsa): /home/demo/.ssh/demo
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in /home/demo/.ssh/demo.
Your public key has been saved in /home/demo/.ssh/demo.pub.
The key fingerprint is:
SHA256:5WkWOOxJ/kJHdp+hpnSmVaZOwS+AkzHOV8d2akt/1pg
The key's randomart image is:
+---[RSA 4096]----+
|        o   ...  |
|       + * o .o .|
|        @ B +.+o |
|       + X = O+o |
|        S B Xo+=.|
|       . * X .E =|
|        . + .  ..|
|         .       |
|                 |
+----[SHA256]-----+

{ demo-keys } master > python user_tool.py add -j users.json -u demo -n demo -k ~/.ssh/demo.pub -t infra -t redteam -t core
('uid:', 6000)
Have a nice day

{ demo-keys } master > git commit users.json

{ demo-keys } master > git commit -m "Adding demo key for walkthrough"

{ demo-keys } master > git push origin master
```

We have now added a key, `demo.pub` for the `demo` user and applied the `redteam`, `infra`, and `core` tags. For more information on that, consult the README in the redteam-ssh repo.

We now need to make this a submodule for our infra repo

```
{ redteam-infra-demo } master > git submodule add https://github.com/tophertimzen/redteam-ssh external/global/host-share/sshkeys
```

You'll want to push and apply those changes as well.

Now you have a ssh key repo setup for your team! Next time you clone off of or fork your master infra repo you can just run


```
git submodule init
git submodule update
```

or do it all over again if you don't want to deal with submodules!

## Setup Infra repo

You will need to configure a few select things in order to spin up homebase

1. Create a git submodule from [redteam-ssh](https://github.com/redteaminfra/redteam-ssh) that contains a valid users.json. The git submodule should be owned by you and placed in `host-share/sshkeys`. You should have at least one user with an `infra` tag. See above instructions for SSH Setup for more detail on how to do this.

We've already done the above!

2. If using cobalt strike, plop a tarball into the puppet module in `puppet/modules/cobaltstrike/files/cobaltstrike.tgz`. If not, there are a few things you'll need to comment out such as all of the references to the `.cobaltstrike.license` in `Vagrantfile` for homebase. You will also want to throw your license `touch external/global/host-share/.cobaltstrike.licence`

Let's just get a trial for cobalt strike for this demo and put a fake licence fill into that file location. If you are not using cobalt strike just remove the `cobaltstrike` module from the homebase `site.pp` in `external/aws/op/homebase/puppet/manifests/site.pp` and the check from the `Vagrantfile` that looks like this

```
begin
  license = File.read("../../../global/host-share/.cobaltstrike.license")
rescue Errno::ENOENT
  STDERR.puts "../../../global/host-share/.cobaltstrike.license does not not exist"
   exit!
end
```

You can get a trial from [here](https://trial.cobaltstrike.com/).

Once done, plop that tgz in `puppet/modules/cobaltstrike/files/`

You can also download the artifact kit and put it in the same directory from above. It will be installed via puppet.

We also want to just touch the license so Vagrant succeeds

`touch external/global/host-share/.cobaltstrike.licence`

3. Put a list of OPs in `external/aws/ips.py` that your company uses for OUTBOUND traffic. This will be used for both SSH inbound and OPSEC rules

For this you will need to consult your organization. Exercise up to the reader! For this demo, we will assume our organization uses an OUTBOUND proxy via 10.10.10.10/32

```
{ aws } master > cat ips.py
#!/usr/bin/env python3
# -*_ coding utf-8 -*-

COMPANY_OUTBOUND = [{'CidrIp': '10.10.10.10/32'}]
```

4. Fill out the CIDRs in `puppet/modules/opsec/files/99-opsec` that your organization owns. These are to prevent OPSEC mistakes from homebase.

For this you will need to consult your organization. Exercise up to the reader! For this demo, we will assume our organization uses the following IPs as their public IP space

```
{ redteam-infra-demo } master > cat puppet/modules/opsec/files/99-opsec
#!/bin/bash

CIDRS="10.10.10.10/32
10.10.9.0/24"
```

5. Add auth for AWS SMS to `puppet/modules/monitoring/files/authFile.yaml`

We will skip this step for now

1. Add OUTBOUND company traffic IPs to `puppet/modules/monitoring/files/C2Compromised.yaml`

We will skip the following, but you'd use the IPs from step 3 into the above file so it looks like the [following](https://github.com/redteaminfra/redteam-infra/tree/master/puppet#monitoring)

1. Add public keys to `external/sketch/provision.sh` inside the `authorized_keys` blob for users you want to access the redirector instances.

You would want a public key, such as the one from demo, to `provision.sh` as seen below.

```
cat <<EOF > ~user/.ssh/authorized_keys
AAAAB3NzaC1yc2EAAAADAQABAAACAQDtTFoNSwWK+zvTUvFlz1P/CeHIP0IK32Yp9tHok3Z1HL6a1YM532+XQYMPxQbQtYaitQDx9hml27MLhhiXrJ1SzhI2KJko5WRX2KZPLq8cUKuJ9snpdFMrXIroRTV+6mCeKAEFuWw7SjwePEVxWBHhM4FeGponhLCm3WD5Zf71kLRsIeVGqDIk+QMGvwiXt6WlRkqzbGZI9nXL5J2Kz7pEA35+d9G2LL9bteho0xYFBrThv/m0nuRVwv9xieUeY0fjCrGia2FM5pc6upYhR+66r96L5v/C0BHAI/89nwR5cARg8f1SnVdO8Rl4+3ATrv0F+3y5vFDR4QM2MC+qBLWvAPtmHFMWxp+/be134MVo5tEY0Gui+dlcsoMk9WMULRpIqSb/FwYBy+1OBXyEBuuZ7ILzCH6BrdN3EaDxdbmAP4JUj52/kIeMXJhA/im0z0puYro5wyET2psL0usmxCtYiNSTUfLRuTtcnTOKF8LNRYW5FCWPIk1kFIG6ZpMfmoKv/4qze51CK+mgnWuWLvySNhhSyptRlx6PhZ2jlw0ZRR393l2ediN0klxqFuBnfyHltnbvcUWFc3XK84TpNULAANBzJqEXFxR0kqiINyCD4lv79rVehZXI/6ydp1IBjf2EF3mQktnJ0GxsvRGljAf6jzOR3OhllyVP7jDNKExFmw==
EOF
```

We'll skip this for now as we use sketch on zero trust proxies. Consult the [README](https://github.com/redteaminfra/redteam-infra/blob/master/external/sketch/README.md) for now

## Make VPC

These commands will be ran from `external/aws`. Make sure that you have sourced your AWS configs from the above Keypairs section

1. `virtualenv -p python3 venv`
1. `. venv/bin/activate`
1. `pip3 install -r requirements.txt`
1. `./make_vpc.py -n <OP NAME>`

You will wind up with a JSON blob for your new VPC.

```
(venv) { aws } master > cat vpc-0ea03eb482236dff0.json
{
    "demo": {
        "region": "us-west-2",
        "vpc_id": "vpc-0ea03eb482236dff0",
        "routing_id": "rtb-0c0fb8d1fa3e17636",
        "subnet_id": "subnet-0b096b12ce7ad0d35",
        "security_groups": {
            "SSH From COMPANY": "sg-01997e72ce6362405",
            "HTTP From COMPANY": "sg-05c6c2b8d41a8393f",
            "HTTPS From Company": "sg-07ca4d00e63a629eb",
            "HTTP From Anywhere": "sg-0ae237fba75201793",
            "HTTPS From Anywhere": "sg-0f119d8ef28740df1",
            "DNS from World": "sg-01cf8b82feb6de6fd",
            "4444 From Company": "sg-03869ac59c14fe381",
            "VPC Allow all traffic": "sg-083980300a94cd414"
        }
    }
}
```

## Spin up a Homebase in that VPC

It is important that you subscribe to the Kali Linux AMI by searching for "ami-0f95cde6ebe3f5ec3" in the AWS marketplace for us-west.

Note: vagrant ssh does not work for reasons I don't fully understand.

1. `./make_boxes.sh`
1. `vagrant plugin install vagrant-aws`
1. `vagrant plugin install vagrant-triggers`
1. `cd /op/homebase`
1. Set the VPC\_JSON env variable to point to the vpc json made above (export VPC_JSON = <FILE>)
1. Set the AWS\_KEY, AWS\_SECRET, AWS\_KEYPATH, environment variables used above
1. Vagrant up --provider aws


After homebase is stood up, plop the SSH Stanza into your ~/.ssh/config as instructed in the output of `vagrant up`

```
    homebase: Created symlink /etc/systemd/system/timers.target.wants/apt-daily.timer → /lib/systemd/system/apt-daily.timer.
==> homebase: Running triggers after up...
==> homebase: Executing command "bash -c vagrant ssh-config >> /tmp/vgrntssh20190314-6881-9yj8ai"...
==> homebase: Command execution finished.
Copy the generated file (homebase-demo) into you ssh config like this:
cat homebase-demo >> ~/.ssh/config
```

You'll want to change the SSH config as well to point to your user and keypair

```
Host homebase-demo
     HostName 54.212.220.85
     User demo
     IdentityFile ~/.ssh/demo
     #Uncomment AddressFamily if you have WSL errors to force ipv4
     #AddressFamily inet
     LocalForward 50050 127.0.0.1:50050
     LocalForward 5000 192.168.1.14:80
     LocalForward 9001 127.0.0.1:9001
     ##Change 59xx to your VNC Port and uncomment this forward. Your UID is found in sshKeys users.json
     #Your port number is (5900 + (UID - 6000) + 1)
     #LocalForward 5901 127.0.0.1:59xx

Host proxy01-demo
     Proxycommand ssh homebase-demo nc -q0 %h.infra.redteam %p
     User demo

Host proxy02-demo
     Proxycommand ssh homebase-demo nc -q0 %h.infra.redteam %p
     User demo

Host elk-demo
     Proxycommand ssh homebase-demo nc -q0 %h.infra.redteam %p
     User demo
     LocalForward 5601 192.168.1.13:5601

Host natlas-demo
     Proxycommand ssh homebase-demo nc -q0 %h.infra.redteam %p
     User demo
```

## Spin up the rest

Now go through and spin up the rest of the boxes in `/op` making sure you still have your AWS creds sourced and the VPC_JSON blob.

1. cd <box>
1. Vagrant up --provider aws

## Hack the Planet

SSH to `homebase-demo` and run `setup-xfc4-vnc` to get everything setup for the enviornment! Now you are good to go in AWS!
