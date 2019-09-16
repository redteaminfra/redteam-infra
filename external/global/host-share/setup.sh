#!/bin/bash -x -e

export DEBIAN_FRONTEND=noninteractive

### Attempt to prevent apt-lock later
apt-get -qq update
apt-get -q -y dist-upgrade
apt-get -q -y auto-remove
apt-get -q -y install unattended-upgrades
unattended-upgrade

### user setup
### Do this early in the setup process so you can get into the box to debug install errors
apt-get -qq -y install python-minimal
bash -c "cd /tmp/host-share/sshkeys/ && python ./user_tool.py apply -j users.json -t core -t infra"

### Install java
apt -y -qq install -f
apt -y -qq install openjdk-8-jre-headless

### Install puppet
if ! grep -q Kali /etc/os-release; then
    wget https://apt.puppetlabs.com/puppet-release-bionic.deb -O /tmp/puppet-release-bionic.deb
    dpkg -i /tmp/puppet-release-bionic.deb
    apt-get -y update
    apt-get -y install puppet
else
    apt-get -y install puppet
fi

if [ ! -d /etc/puppet/modules ]; then
    mkdir -p /etc/puppet/modules
fi

### Install puppet modules
### Versions are hardcoded as a result of installation errors
### Versions came from https://forge.puppet.com/elastic and https://forge.puppet.com/puppetlabs

# Install puppetlabs apt module
puppet module install puppetlabs-apt --modulepath /etc/puppet/modules

# Install logstash for everybody
puppet module install elastic-logstash --version 5.1.0 --modulepath /etc/puppet/modules

if grep -q homebase /etc/hostname; then
    puppet module install dp-golang --modulepath /etc/puppet/modules
    puppet module install puppetlabs-postgresql --modulepath /etc/puppet/modules
fi

### Install golang on homebase
if grep -q homebase /etc/hostname; then
    puppet module install dp-golang --modulepath /etc/puppet/modules
    puppet module install puppetlabs-postgresql --modulepath /etc/puppet/modules
fi

### Install puppet tools for elk
if grep -q elk /etc/hostname; then
    wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-5.6.15.deb -O /tmp/elasticsearch.deb
    dpkg -i /tmp/elasticsearch.deb
    apt -y install -f
    ### Super gross fix to get us to 5.4.3 of elastic-elasticsearch
    ### Cannot install older version first
    ### Causes dependancy problems
    ### TODO: Fix this
    #puppet module install elastic-elasticsearch  --modulepath /etc/puppet/modules
    puppet module install elastic-elasticsearch --version 5.4.3 --modulepath /etc/puppet/modules --force
    #puppet module install elastic-kibana --modulepath /etc/puppet/modules
    puppet module install elastic-kibana  --version 5.1.0 --modulepath /etc/puppet/modules --force
fi

### fix base image provision
regex="(ubuntu|ec2-user):x:.*"
if [[ `cat /etc/passwd` =~ $regex ]]
then
    usermod -p'*' ${BASH_REMATCH[1]}
fi

### make kali rolling auto-update
if grep -q Kali /etc/os-release; then
    cat <<EOF > /etc/apt/apt.conf.d/99kaliunattended
Unattended-Upgrade::Origins-Pattern {
        "o=*";
}
EOF
fi

### disable ipv6
cat <<EOF >> /etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sysctl -p

### ssh fixes
sed -i -e 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config
sed -i -e 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl reload ssh.service

### out of the box, ubuntu has '!' in shadow
if grep -q ubuntu /etc/passwd; then
    usermod -p '*' ubuntu
fi

### bootstrap puppet env
echo "vpc=$(/bin/bash -c /bin/hostname | /usr/bin/cut -d '-' -f2- | tr -d '\n')" >> /etc/profile.d/puppet.sh
echo "subnet=$(hostname -I | cut -d. -f1-3)" >> /etc/profile.d/puppet.sh

bash -c "cd /tmp/host-share/puppet && time puppet apply --modulepath=/etc/puppet/modules:/tmp/host-share/puppet/modules/ --verbose --debug manifests/site.pp"
