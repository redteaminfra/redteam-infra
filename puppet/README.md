# WTF

Firstly, apologies for the awkwardness of this overall architecture.  While this solution may not occur to you first when thinking how to solve this problem, in discussions it became clear that this was probably the simplest and safest architecture we could come up with.  Our requirements that led us down this path are:

* Repeatable

Must be able to be built the same way in multiple places and on multiple platforms with ease.  Automation minimizes the chance the mistakes happen in instantiating copies of infrastructure setups.

* Modularity

Must provide a way of breaking down infrastructure tasks so that we can rapidly change our infrastrucutre to match requirements of operations without breaking things at the same time.

* Dyanmic

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

1. vagrant up
1. hack; hack; hack
1. ```git add; git commit```
1. ```git push homebase-xxx:/var/lib/git/infra```
1. ????
1. ```git push origin master```
1. Profit!!

## Hard Mode

This lets you play with changes in master on homebase, then pretty it
up in a branch on your machine prior to pushing to github.

1. vagrant up
1. ssh into homebase
  1. ```git clone /var/lib/git/infra```
  1. ```cd infra```
  1. ```BASELINE=$(git rev-parse HEAD)```
  1. hack; hack; hack
  1. ```git add; git commit```
  1. ```git push```
  1. ```git format-patch $BASELINE```
1. ```scp 'homebase-xxx:infra/*patch' .```
1. ```git checkout -b topic```
1. ```git am < *.patch```
1. rebase; rebase; rebase
1. ```git checkout master```
1. ```git merge topic```
1. ```git push origin master```
1. ????
1. Profit!

# Puppet Modules for Infra

## cobaltstrike

1. Add a teamserver password in the `PASSWORD` field in `modules/cobaltstrike/files/teamserver.sh`
1. Change the Malleable C2 Profile you want to use in `modules/cobaltstrike/files/teamserver.sh`. Profiles are located in `/opt/malleable/`
1. When connecting to Cobalt Strike on AWS you can connect with an SSH LocalForward from the ssh-config output. `ssh -f -N vm-vpc'

Our infra supports both "staged" and "stageless" beacons. To do either of the following:

1. Create a listener by setting the "Host" field to one of your external proxy IP addresses. Note: This restricts us to only being able to use one proxy for our teamserver due to Mudge not supporting n+1 currently. We will do this to support staged beaconing.
1. Stageless: Simply create a stageless executable. Ignore the proxy settings.
1. Staged: Simply create an artifact beacon

If you want to only use staged beacons to support N+1 proxies. This method will NOT support staged beacons/

1. Create a listener by setting the "host" field to the team server IP address and add the proxy IPs as the external beacons.
1. Create a stageless beacon with a Proxy of one of the AWS IPS. For example `http://AWS-IP:80` in the stageless beacon configuration.

Cobalt Strike also contains a `c2-monitor.cna` aggressor script that runs as a headless script to provide the ELK instance with beacon information useful for alerting. This script will keep track of cobalt strike beacons and will alert an operator when they timeout or don't phone back within a certain threshold. It will also keep track of beacon state if the team server is restarted. 

## Mod Rewrite

This module is used on the proxies to perform a mod_rewrite on apache to redirect CobaltStrike C2 traffic back to homebase.
This module requires a Malleable C2 profile and a redirection URL for invalid C2 URI's.

Currently this module only supports the amazon C2 profile. Work is in progress to automate the C2 modrewriter.

## gitpuppet

This module periodically checks out the modules of a git tree hosted
by the server created in gitserver and applies the changes.  The
important moving parts:

* `/etc/infra`

This is where `site.pp` is stored and where `git-puppet-apply.sh`
lives, which checks out the git repo and applies the changes

## gitserver

This module sets up a git server that holds the puppet modules.  It
uses a tarball of this very git repo, which is created on `vagrant up`
by the vagrant plugin vagrant-triggers.

* `/var/lib/git/infra`

This is the git repo that is this git repo.  The redteam group can
push to the repo and changes are automatically applied.

* git-daemon

Homebase runs a git-daemon that other machines can periodically pull
from and apply in a similar way.

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

  * asciinema is blackholed to prevent accidental asciinema upload mistakes


## ssh

The idea behind this module is to manage user creation/deactivation
cleanly and repeatably. The ssh keys and user identities are stored in
an internal github project.  This basically means that we have a VM on
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

## IPTables

Homebase has a set of iptables rules to prevent new outbound
connections to <victim.target> DMZ IP space.  This is designed to prevent an
opsec mistake of running an exploit or scan from homebase.  Users
should instead use one of the proxy boxes for attack traffice.

## OPSEC

This module is applied to homebase to prevent it from being able to do anything outbound to your companies IP address space.  

The IPs in this module should all of the CIDR ranges your company uses. Consult an ASN record or your companies internal documentation for this information. 

## Logging

Logging is being done with an elastic stack running on elk-vpc. This is
provisioned in two ways. Because we aren't using puppet librarian we needed
a way to have modules supported from the forge. These are installed
in the shell provisioner stage and then utilized in the site manifests.
ELK server will have Kibana and Elastic while all other machines in the VPC
ship logs to it with logstash.

## Natlas

Natlas will spin up an [natlas instance](https://github.com/natlas/natlas) for port scanning. It includes an nmap-agent and an natlas systemd service.

There are two modules, one for the server and one for the agent in `natlasserver` and `natlasagent`

## IRC

IRC will stand up a very minimal miniircd IRC Server.
IRC default listens on port 6667. A sed command is used to ensure s.bind() is on localhost.

## Homebase tools

A small collection of packages that are useful for homebase operations.

## Unattended Upgrades

Manages a file that ought to keep unattended upgrades working and installs the packages

## Etherpad

Stands up a local instance of Etherpad for collaborative note-taking.

Etherpad is on 127.0.0.1:9001 and is locally forwarded with SSH

## Mollyguard

Installs the `mollyguard` package to force typing in the hostname to avoid accidental reboots.

## Tinyproxy

Installs [tinyproxy](https://tinyproxy.github.io/) on the proxies.  This is a very simple http proxy that allows 192.168.0.0/16 to use it.  All ports are available for CONNECT, so you can effectively use this as an arbitrary tcp proxy.  Using depends on application, but in general, environment variables will do for most tools:

```
http_proxy=http://192.168.1.11:8888/
https_proxy=$http_proxy
curl http://example.com
```

## Monitoring

This module will create rules to alert on within the ELK instance using elastalert.

`C2Dead.yaml` will alert an operator when a beacon exceeds a threshold as defined in the cobaltstrike file `c2-monitor.cna`. 

`C2Compromised.yaml` will alert an operator when a proxy server (hosting your domain / first entry point to C2) is hit by your organizations IP space without a successful htaccess redirect. This is a pretty sure sign that your blue team has hunted you down and you need to be ready to move proxies or get a game plan going! 

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