#!/bin/bash -x -e
# Copyright (c) 2023, Oracle and/or its affiliates.

# user setup
bash -c "cd /tmp/host-share/sshkeys/ && chmod +x *.py && python3 ./user_tool.py apply -j users.json -t core"

# run apply puppet
bash -c "cd /tmp/host-share/puppet && time sudo puppet apply --modulepath=/etc/puppet/modules:/tmp/host-share/puppet/modules/ --verbose --debug manifests/site.pp"
