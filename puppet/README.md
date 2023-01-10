# WTF

Firstly, apologies for the awkwardness of this overall architecture.  While this solution may not occur to you first when thinking how to solve this problem, in discussions it became clear that this was probably the simplest and safest architecture we could come up with.  Our requirements that led us down this path are:

* Repeatable

Must be able to be built the same way in multiple places and on multiple platforms with ease.  Automation minimizes the chance the mistakes happen in instantiating copies of infrastructure setups.

* Modularity

Must provide a way of breaking down infrastructure tasks so that we can rapidly change our infrastructure to match requirements of operations without breaking things at the same time.

* Dynamic

Must provide mechanism  for changes to be deployed across a network of machines at once, so that changes in config rapidly deploy to the infrastructure.

* Auditable

Must have ability to verify configuration is deployed as per specification.

* Secure

Must not require having unnecessary information exposed outside of <target.victim>.

With this in mind, we have a git server/git client model for storing puppet configuration.  Homebase serves as our git server and all other machines in the VPC/zone will periodically check out the git repo (this very git repo) and apply the state.

# Development Workflow

As with everything, there is more than one way to do it.  If you don't know what you are doing, probably easiest to stick with Easy Mode.

## Easy Mode

Note!  The workflow below only works on the master branch

1. terraform apply
2. hack; hack; hack
3. ```git add; git commit```
4. ```git push homebase-xxx:/var/lib/git/infra```
5. ????
6. ```git push origin master```
7. Profit!!

## Hard Mode

This lets you play with changes in master on homebase, then pretty it
up in a branch on your machine prior to pushing to GitHub.

1. terraform apply
2. ssh into homebase
3. ```git clone /var/lib/git/infra```
4. ```cd infra```
5. ```BASELINE=$(git rev-parse HEAD)```
6. hack; hack; hack
7. ```git add; git commit```
8. ```git push```
9. ```git format-patch $BASELINE```
10. ```scp 'homebase-xxx:infra/*patch' .```
11. ```git checkout -b topic```
12. ```git am < *.patch```
13. rebase; rebase; rebase
14. ```git checkout master```
15. ```git merge topic```
16. ```git push origin master```
17. ????
18. Profit!

# Puppet Modules for Infra

## Back-flips

This module sets up the infrastructure to use "ssh back-flips" A
back-flip is where the victim will ssh back to the attacker with a remote
port forward back to the victim's ssh port. This enables the attacker
to ssh directly back into the victim to get a shell as well as set up
a SOCKS5 proxy into the victim network.

## Cleanup

Uses `tidy` to eliminate large stashes of logs such as those found in /var/cache/puppet/report.

## cobaltstrike

1. Add a teamserver password in the `PASSWORD` field in `modules/cobaltstrike/files/teamserver.sh`
2. Change the Malleable C2 Profile you want to use in `modules/cobaltstrike/files/teamserver.sh`. Profiles are located in `/opt/malleable/`
3. When connecting to Cobalt Strike on AWS you can connect with an SSH LocalForward from the ssh-config output. `ssh -f -N vm-vpc'

Our infra supports both "staged" and "stageless" beacons. To do either of the following:

1. Create a listener by setting the "Host" field to one of your external proxy IP addresses. Note: This restricts us to only being able to use one proxy for our teamserver due to Mudge not supporting n+1 currently. We will do this to support staged beaconing.
2. Stageless: Simply create a stageless executable. Ignore the proxy settings.
3. Staged: Simply create an artifact beacon

If you want to only use staged beacons to support N+1 proxies. This method will NOT support staged beacons/

1. Create a listener by setting the "host" field to the team server IP address and add the proxy IPs as the external beacons.
2. Create a stageless beacon with a Proxy of one of the AWS IPS. For example `http://AWS-IP:80` in the stageless beacon configuration.

Cobalt Strike also contains a `c2-monitor.cna` aggressor script that runs as a headless script to provide the ELK instance with beacon information useful for alerting. This script will keep track of cobalt strike beacons and will alert an operator when they time out or don't phone back within a certain threshold. It will also keep track of beacon state if the team server is restarted.

## Dante

[Dante](https://www.inet.no/dante/) is a SOCKS5 server running on the proxies. It is configured to listen on port 1080 on the internal network. You can use it for command line tools that don't have explicitly socks support by crafting a proxychains.conf similar to below.

```
strict_chain
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5  192.168.2.11 1080
EOF
```

You would then invoke CLI tool as `proxychains <cli tool>` to proxy through the socks server

## Elastickibana

Installs Elasticsearch and Kibana on the ELK instance with a docker-compose file.

## Etherpad

Stands up a local instance of Etherpad for collaborative note-taking.

Etherpad is on 127.0.0.1:9001 and is locally forwarded with SSH

## gitpuppet

This module periodically checks out the modules of a git tree hosted
by the server created in gitserver and applies the changes.  The
important moving parts:

* `/etc/infra`

This is where `site.pp` is stored and where `git-puppet-apply.sh`
lives, which checks out the git repo and applies the changes

## gitserver

This module sets up a git server that holds the puppet modules.  It
uses a tarball of this very git repo, which is created on `terraform apply`.

* `/var/lib/git/infra`

This is the git repo that is this git repo.  The redteam group can
push to the repo and changes are automatically applied.

* git-daemon

Homebase runs a git-daemon that other machines can periodically pull
from and apply in a similar way.

## gophish

Sets up gophish listening on 3333 and 443 with a snakeoil cert

## Homebase tools

A small collection of packages that are useful for homebase operations.

## Hosts

* host file
  * use the vpc json blob to make the hosts file
  * upon making homebase, it'll spit out host file stanza to put on your computer something like: ```123.123.123.123 homebase-a.nonsense.nothing```  The machines in the vpc will have their host files populated as something like:

  ```
  192.168.1.10 homebase-a.nonsense.nothing
  192.168.1.11 proxy01-a.nonsense.nothing
  192.168.1.12 proxy02-a.nonsense.nothing

  127.0.0.1 asciinema.org
  ```

  * asciinema is black-holed to prevent accidental asciinema upload mistakes

## Hostsexternal, internal and hb

Silly bootstrapper to assign every instance a realistic hostname via ruby erb. This is necessary and rather annoying.

## IRC

IRC will stand up a very minimal miniircd IRC Server.
IRC default listens on port 6667. A sed command is used to ensure s.bind() is on localhost.

## Logstashconfig

Applied to all instances, so they know how to ship logs to the ELK instance.

Logging is being done with an elastic stack running on elk-vpc. This is
provisioned in two ways. Because we aren't using puppet librarian we needed
a way to have modules supported from the forge. These are installed
in the shell provisioner stage and then utilized in the site manifests.
ELK server will have Kibana and Elastic while all other machines in the VPC
ship logs to it with logstash.

Contains files that tell instances which files to pipe through logstash.

## Loot

Creates `/loot` to store loot. We need a more secure way to handle loot, and it is a change inbound.

## Mod Rewrite

This module is used on the proxies to perform a mod_rewrite on apache to redirect CobaltStrike C2 traffic back to homebase.
This module requires a Malleable C2 profile and a redirection URL for invalid C2 URI's.

Currently, this module only supports the amazon C2 profile. Work is in progress to automate the C2 modrewriter.

## Mollyguard

Installs the `mollyguard` package to force typing in the hostname to avoid accidental reboots.

## Monitoring

This module will create rules to alert on within the ELK instance using elastalert.

`C2Dead.yaml` will alert an operator when a beacon exceeds a threshold as defined in the cobaltstrike file `c2-monitor.cna`.

`C2Compromised.yaml` will alert an operator when a proxy server (hosting your domain / first entry point to C2) is hit by your organizations IP space without a successful htaccess redirect. This is a pretty sure sign that your blue team has hunted you down, and you need to be ready to move proxies or get a game plan going!

To configure C2Compromised to alert on IPs hitting you, reference your external OUTBOUND IPs as defined from the README in `external`.

```
filter:
- query:
    query_string:
      query: "host: proxy* AND \"200\" AND NOT \"/s/ref\" AND (client: [IP TO IP]  OR client: [IP TO IP] )"
```

To configure both of these, make sure you fill out the "email" section in both of the aforementioned files. The authors have used phone numbers in the past

```
email:
- "<PHONE OF OPERATOR 1>@domain"
- "<PHONE OF OPERATOR 1>@domain"
```

You'll also need to add auth for AWS SMS if you go this route in `puppet/modules/monitoring/files/authFile.yaml`.

## Natlas

Natlas will spin up a [natlas instance](https://github.com/natlas/natlas) for port scanning. It includes a nmap-agent and a natlas systemd service.

There are two modules, one for the server and one for the agent in `natlasserver` and `natlasagent`

## nfsserver

Installs `nfs-kernel-server`. Configures an NFS share (`/dropbox` on homebase) available to the 192.168.2.0/24 subnet. Sets the user/group of the `/dropbox` folder to `nobody:redteam` and the permissions to `770`.

## nfsclient

Ensures `nfs-common` is installed. Configures `/etc/fstab` to connect to homebase and mounts `/dropbox` on client hosts (proxy servers by default).

## Nmap

Bootstraps the installation of `nmap 7.60` because at the time our instances did not automatically install it.

## Open Resty

Installs Open Resty to proxies, so we can use nginx with Proxy Protocol, as well as all the extendable features Open Resty provides

## OPSEC

Homebase has a set of iptables rules to prevent new outbound
connections to <victim.target> DMZ IP space.  This is designed to prevent an
opsec mistake of running an exploit or scan from homebase.  Users
should instead use one of the proxy boxes for attack traffic.

The IPs in this module should be all the CIDR ranges your company uses. Consult an ASN record or your companies internal documentation for this information.

## PCV

This module will bring up the PCV C2 server, web interface and spawn appropriate listeners.

## Proxytools

A variety of tools installed on the proxies.

## sketchopsec

Provisions OPSEC firewall rules for sketch instances. Ensures that only the middle sketch boxes can be reached from proxies, and blocks all connections to edges.

## ssh

The idea behind this module is to manage user creation/deactivation
cleanly and repeatably. The ssh keys and user identities are stored in
an internal GitHub project.  This basically means that we have a VM on
an internal resource that pushes to homebase every time something is pushed to the
ssh keys repo on github.com/redteaminfra/redteam-ssh

The moving parts:
```
                                  +
                                  |
                                  |
                                  |
                                  |
                                  |
+-----------------+               |    +------------------+
|                 |               |    |                  |
|     github      |               |    |                  |
|                 |  +---------------->+    homebase      |
|                 |  |            |    |                  |
+------+----------+  |            |    +------------------+
       ^             |            |
       |             |            |        VPC A
       |             |            +---------------------------------+
       |             |            |        VPC B
       |             |            |
       |             |            |
+------+-----------+ |            |    +------------------+
|                  | |            |    |                  |
|  internal host   +------------------>+                  |
|                  |              |    |     homebase     |
|                  |              |    |                  |
+------------------+              |    +------------------+
                                  |
                                  |
                                  |
                                  |
                                  |
                                  |
                                  |
  intranet                        |
                                  |
                                  +

```

Each homebase machine has a repo for users and ssh keys, which a VM on
an internal host periodically pulls from github.com/redteaminfra/redteam-ssh  and pushes to.
Puppet then periodically checks out the repo and runs a script that
applies the changes.

### Use Cases Supported

* New User adding new key
* User removal
* User changing keys
* User changing name

## sshproxy

Allows for local port forwarding across sketch infrastructure such that a remote SSH connection can be used as a proxy.

## Tinyproxy

Installs [tinyproxy](https://tinyproxy.github.io/) on the proxies.  This is a very simple http proxy that allows 192.168.0.0/16 to use it.  All ports are available for CONNECT, so you can effectively use this as an arbitrary tcp proxy.  Using depends on application, but in general, environment variables will do for most tools:

```
http_proxy=http://192.168.1.11:8888/
https_proxy=$http_proxy
curl http://example.com
```

## Unattended Upgrades

Manages a file that ought to keep unattended upgrades working and installs the packages

## Volunteer SSH

Allows SSH keys with the volunteer tag to SSH to this instance. Consult [RedTeam-ssh](https://github.com/redteaminfra/redteam-ssh) for more detail on tags.

## waybackdownloader

Installs the wayback\_machine\_downloader gem

## Yama

Disable ptrace!