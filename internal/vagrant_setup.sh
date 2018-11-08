#!/bin/bash

### Disable apt timer
systemctl disable apt-daily.timer

### Updates
apt-get -y update && apt-get -y dist-upgrade && apt-get -y autoremove || exit 1

### Upgrades
apt-get install -y unattended-upgrades || exit 1
echo 'Unattended-Upgrade::Automatic-Reboot "true";' >> /etc/apt/apt.conf.d/50unattended-upgrade

### Install puppet
regex="Version: ([0-9])\.([0-9])\.([0-9]).*"
if [[ `apt-cache show puppet` =~ $regex ]] && [[ ${BASH_REMATCH[1]} -lt 4 ]]
then
   cd ~ && wget https://apt.puppetlabs.com/puppetlabs-release-pc1-trusty.deb
   sudo dpkg -i puppetlabs-release-pc1-trusty.deb
   sudo apt-get -y update
   sudo apt-get install -y puppet-agent || exit 1
   ln -s /opt/puppetlabs/bin/puppet /usr/bin/puppet
else
   sudo apt-get -y install puppet || exit 1
fi

puppet module install elastic-logstash --version 5.1.0 --modulepath "/etc/puppet/modules"
puppet module install puppetlabs-apt --version 4.3.0 --modulepath "/etc/puppet/modules"

### Install git
apt-get -y install git

### user setup
apt-get -y install python-minimal
bash -c "cd /tmp/host-share/sshkeys/ && ./user_tool.py apply -j users.json -t volunteer -t core"

### ssh fixes
sed -i -e 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config
sed -i -e 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
/etc/init.d/ssh reload

### internal host firewall
ufw allow ssh
ufw allow http
ufw allow https
ufw allow 4444
ufw enable
