#!/bin/bash
# Copyright (c) 2023, Oracle and/or its affiliates.


DIR=$(mktemp -d)
VPC=$(hostname | /usr/bin/cut -d '-' -f2- | tr -d '\n')
gitserver="homebase-$VPC.infra.redteam"

cd $DIR && \
    git clone git://$gitserver/git/sshkeys && \
    cd sshkeys && \
    ./user_tool.py apply -j users.json $(/etc/infra/ssh_tags.py) && \
    cd ..
rm -rf $DIR
