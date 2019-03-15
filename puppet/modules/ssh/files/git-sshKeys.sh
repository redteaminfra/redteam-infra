#!/bin/bash

DIR=$(mktemp -d)
VPC=$(hostname | /usr/bin/cut -d '-' -f2- | tr -d '\n')
gitserver="homebase-$VPC.infra.redteam"

cd $DIR && \
    git clone git://$gitserver/git/sshKeys && \
    cd sshKeys && \
    ./user_tool.py apply -j users.json $(/etc/infra/ssh_tags.py) && \
    cd ..
rm -rf $DIR
