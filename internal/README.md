# Internal Infra

1. Use packer to make a ubuntu box and name it `internal`
1. `sudo make-network.sh`
1. perform the below steps and run `vagrant up` on each box needed

```
vagrant plugin install vagrant-libvirt
vagrant plugin install vagrant-proxyconf
vagrant plugin install vagrant-triggers
git submodule init
git submodule update
vagrant up
```

## How to Play

Because vagrant makes a local .vagrant folder to house all information about an instance, we need a copy of that repository for every operation we spin up on an internal host. On the chance that a change is required for the infrastructure a fork is deal.

1. Fork https://github.com/redteaminfra/redteam-infra on github.com
1. git clone <forkurl> <engadgement name>
1. `make-network.sh <name of engagement>`
1. Push changes to fork and if needed push them to infrastructure

## Boxes to Standup

1. Homebase
1. Natlas
1. ELK

## Virbr

To create a new network, run `make-network.sh` as a super user.

## Destory a Network Virbr

```
vagrant destroy # on all boxes
virsh net-undefine <Network-Name>
virsh net-destroy <Network-Name>
```
