#!/bin/bash -e

DIR=$(mktemp -d)
VPC=$(hostname | /usr/bin/cut -d '-' -f2- | tr -d '\n')
gitserver="homebase-$VPC.infra.redteam"

cd $DIR && \
    git clone git://$gitserver/git/infra && \
    cp -v infra/$(readlink /etc/infra/site) /etc/infra/site.pp ; \
    puppet apply --modulepath=infra/puppet/modules/:/etc/puppet/modules/ /etc/infra/site.pp && \
    cd ..
rm -rf $DIR
