# WTF

This is the home for scripts to automagically create a new perfect
sphere of hacking.

The basic idea is that each enagement has its own VPC that
encapsulates all data for that engagement.  This keeps things from
being cross-contaminated between parallel and past engagements and
minimizes that data we have exposed in AWS at any one time.  It also
helps keep our system architecture sane and auditable.

Each operation, as noted above will have a VPC.  This also enables us
to create a staging VPC to try out infrastructure changes that need to
happen prior to or during an engagement.

# VPC Structure

Each VPC uses the same internal IP space of 192.168.0.0/16.  We use
the subnet of 192.168.0.0/24 for now.  If needed, we can use other
subnets.

## Machines in an operation VPC

* Homebase (192.168.0.2)

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
   192.168.0.3   proxy-1.op-example.infra.redteam
   192.168.0.4   proxy-2.op-example.infra.redteam
   192.168.0.5   proxy-3.op-example.infra.redteam
   ```

   This way, one can ssh into the VPC with the following snippet in .ssh/config:
   ```
   Host *.op-example.infra.redteam
      ProxyCommand tsocks ssh op-example.infra.redteam nc -q0 %h 22
   ```

  For testing purposes use t2.medium as machine type ($0.0464 per
  Hour) currently.  However, for operations, please use m4.4xlarge as
  machine type ($0.8 per Hour) currenlty.  See homebase/Vagrantfile

* Proxy Machines

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
  Additionally, each proxy has an http proxy listening on port 8888 on
  the private network.

* Elastic Stack Machine

  This machine functions as our centralized logging server. It contains an elastic stack
  (elasticsearch, logstash, kibana).

  All logs from machines in the VPC are sent to the Elastic Stack.

* Natlas

  A dedicated natlas instance providing port scanning capabilities as well as
  the web interface to see the results.

## Machine standup order

In order to successfully standup machines in the VPC for operations, the machines should be broughtup in the following order.

1. homebase
1. proxies
1. Natlas
1. elkServer

After homebase is deployed you will need to edit the SSH stanza in order for proxies, natlas, and elkServer to successfully deploy. Vagrant spits out a command for this and modifies `~/.ssh/config`

Once homebase is deployed, just change directories to each of the other boxes.

There are a few puppet modules you will need to modify for every op. View what to change in the `puppet/README`

1. Cobalt Strike
1. Mod Rewrite

Additionally follow the directions in `Setup Rules for VPC`

## SSH Setup

The infra repo makes use of submodules for SSH from [redteam-ssh](https://github.com/redteaminfra/redteam-ssh), make sure to create those as submodules or init those if cloning a staged repo (vagrant will yell at you if you don't)

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

Ensure SSHKEY repo is up to date

1. `cd external/aws/host-share/sshkeys`
1. `git pull origin master`
1. `git commit sshkeys`

## Enabling HTTPS CS Beacons

This is a manual process, partly becuase it involves configuration of presently non-automated DNS settings.  The result of this flow, rather than to commonly documented flows is that in this flow, we have SSL terminated at the proxies.  There are 4 moving parts here:

* DNS server for your domain
* Proxies
* Cobalt Strike Server
* Cobalt Strike Beacons

Procedure:

1. Make two A records for domain, .domain and www.domain (for example .fuuu.party and www.fuuu.party).  Point these to a proxy
1. Get letsencrypt certs for your domain on the proxies.  Select HTTP->HTTPS redirect
1. Edit the generated http conf that let's encrypt drops (000-default-le-ssl.conf) to include the lines:
```
SSLProxyEngine on
SSLProxyVerify none
SSLProxyCheckPeerCN off
SSLProxyCheckPeerName off
SSLProxyCheckPeerExpire off
```
1. Reload apache.
1. Test with curl.
1. Setup https reverse listeners on cobalt strike. Set domain to IP and A record for this proxy.
1. Drop binaries on target and get listeners

## Enabling Automatic SSH sync

To make ssh updates go automatically from internal github to deployed aws machines, ssh to internal host and sudo su into sshsyncrobot (this will be fixed soon) and run sync_tool add -i <ip>, where ip is the ip address of your newly deployed homebase.
