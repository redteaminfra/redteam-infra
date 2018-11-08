#!/bin/bash

### Puppet dependancies

modulepath="/etc/puppet/modules"

mkdir -p $modulepath

puppet module install elastic-elasticsearch --version 5.4.3 --modulepath $modulepath
puppet module install elastic-kibana --version 5.1.0 --modulepath $modulepath
