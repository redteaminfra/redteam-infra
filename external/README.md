# WTF

This is the home for scripts to automagically create a new perfect
sphere of hacking.

The basic idea is that each engagement has its own VPC that
encapsulates all data for that engagement.  This keeps things from
being cross-contaminated between parallel and past engagements and
minimizes that data we have exposed in a cloud provider at any one time.  It also
helps keep our system architecture sane and auditable.

Each operation, as noted above will have a VPC.  This also enables us
to create a staging VPC to try out infrastructure changes that need to
happen prior to or during an engagement.

# VPC Structure

Each VPC uses the same internal IP space of 192.168.0.0/16. Within that, we use 3 subnets

192.168.0.0/24 is our bastion / homebase subnet

192.168.1.0/24 is our logging and subnet

192.168.2.0/24 is our proxy subnet

## Machines in an operation VPC

* Homebase (192.168.0.10)

   Each VPC has at least one machine, named homebase, which is a kali
   box with ssh open to target.victim.  It hosts things like cobalt strike and
   empire and other tools as needed.  This machine is the one that we
   connect to do operate the other machines within the VPC and is the
   only machine that should be having incoming connections from target.victim
   that are not C2 traffic.

   This machine should never make outgoing connections to target.victim and
   will have a security group in place to prevent opsec mistakes.

   To facilitate easier ssh config, this machine will have an A record
   on the infra.redteam domain.  For example, if the public IP was
   123.456.789.012, op-example.inc.red, would point to that IP.  The
   /etc/hosts file on this machine contains entries for the other
   machines in the VPC as subdomains of the A record.  For example:
   ```
   192.168.2.11   proxy-1.op-example.infra.redteam
   192.168.2.12   proxy-2.op-example.infra.redteam
   192.168.2.13   proxy-3.op-example.infra.redteam
   ```

  For testing purposes use t2.medium as machine type ($0.0464 per
  Hour) currently.  However, for operations, please use m4.4xlarge as
  machine type ($0.8 per Hour) currently.

* Elastic Stack Machine (192.168.1.13)

  This machine functions as our centralized logging server. It contains an elastic stack
  (elasticsearch, logstash, kibana).

  All logs from machines in the VPC are sent to the Elastic Stack.

* Natlas (192.168.1.14)

  A dedicated natlas instance providing port scanning capabilities as well as
  the web interface to see the results.

* Proxy Machines (192.168.2.0/24)

  These are the machines that receive C2 traffic from target.victim proxies
  are therefore indictable by defenders.  They need They serve two proxy
  functions, forward and reverse.

  They reverse proxy incoming connections from target.victim proxies
  (http/https traffic) to homebase or other C2 servers as need arises.
  These machines require FQDN for certificates.  SSL can be terminated
  at either the proxy machine or the C2 machine depending on what the
  server supports.

  The forward proxy is to forward attack traffic from homebase or
  other attack machines back to target.victim.  Each proxy machine has a socks
  proxy on port 1080 that is listening on the private 192.168.0.0/16
  network, to allow use as a forward proxy within the VPC.
  Additionally, each proxy has a http proxy listening on port 8888 on
  the private network.

# Setup

## Setup restrictions

There are a few puppet modules you will need to modify for every op. View what to change in the `puppet/README`

1. Cobalt Strike
2. Mod Rewrite

Additionally, follow the directions in `Setup Rules for VPC`

## Repo Setup

Because terraform makes a local folder to house all information about state, we need a copy of this repository for every infra we deploy.

1. git clone https://github.com/redteaminfra/redteam-infra <OPNAME>
2. Make a new repo in RedTeamInfra called <OPNAME>
3. git remote rm origin
4. git remote add origin git@github.com:redteaminfra/<OPNAME>
5. git push origin master

Once the repo is forked and cloned, you may need to make some additional modifications to the puppet modules depending on your use cases. View the README in the puppet repo for additional documentation.

## What to do

In order to start an OP VPC you will need to

1. fork repo to https://github/Intel/redteam-infra/
2. change homebase to m4.4xlarge
3. change ELK to t2.large

## Setup Rules for VPC

You will need to configure a few select things in order to spin up homebase

1. Create a git submodule from [redteam-ssh](https://github.com/redteaminfra/redteam-ssh) that contains a valid users.json. The git submodule should be owned by you and placed in `host-share/sshkeys`. You should have at least one user with an `infra` tag. See above instructions for SSH Setup (in /external/README.md) for more detail on how to do this.
2. If using cobalt strike, plop a tarball into the puppet module in `puppet/modules/cobaltstrike/files/cobaltstrike.tgz`. Also, put your licence in `/global/host-share/.cobaltstrike.licence`
3. Fill out the CIDRs in `puppet/modules/opsec/files/99-opsec` that your organization owns. These are to prevent OPSEC mistakes from homebase.
4. Add auth for AWS SMS to `puppet/modules/monitoring/files/authFile.yaml` if using AWS SMS for alerting
5. Add OUTBOUND company traffic IPs to `puppet/modules/monitoring/files/C2Compromised.yaml`
6. Add public keys to `external/sketch/provision.sh` inside the `authorized_keys` blob for users you want to access the redirector instances.

For each individual cloud, consult the README in the cloud providers folder.

## SSH Setup

The infra repo makes use of submodules for SSH from [redteam-ssh](https://github.com/redteaminfra/redteam-ssh), make sure to create those as submodules or init those if cloning a staged repo

```
git clone <Your redteam-ssh repo with team keys in it> # git clone https://github.com/redteaminfra/redteam-ssh
cd redteam-infra/external/aws
git submodule add https://github.com/redteaminfra/redteam-ssh host-share/sshkeys
```

OR if you have a submodule already defined

```
git submodule init
git submodule update
```

Ensure SSHKEY repo is up-to-date

1. `cd external/aws/host-share/sshkeys`
2. `git pull origin master`
3. `git commit sshkeys`

## Enabling HTTPS CS Beacons

This is a manual process, partly because it involves configuration of presently non-automated DNS settings.  The result of this flow, rather than to commonly documented flows is that in this flow, we have SSL terminated at the proxies.  There are 4 moving parts here:

* DNS server for your domain
* Proxies
* Cobalt Strike Server
* Cobalt Strike Beacons

Procedure:

1. Make two A records for domain, .domain and www.domain (for example .fuuu.party and www.fuuu.party).  Point these to a proxy
2. Get letsencrypt certs for your domain on the proxies.  Select HTTP->HTTPS redirect
3. Edit the generated http conf that let's encrypt drops (000-default-le-ssl.conf) to include the lines:
```
SSLProxyEngine on
SSLProxyVerify none
SSLProxyCheckPeerCN off
SSLProxyCheckPeerName off
SSLProxyCheckPeerExpire off
```
1. Reload apache.
2. Test with curl.
3. Setup https reverse listeners on cobalt strike. Set domain to IP and A record for this proxy.
4. Drop binaries on target and get listeners

## Enabling Automatic SSH sync

To make ssh updates go automatically from internal GitHub to deployed aws machines, ssh to internal host and sudo su into sshsyncrobot (this will be fixed soon) and run sync_tool add -i <ip>, where ip is the ip address of your newly deployed homebase.
