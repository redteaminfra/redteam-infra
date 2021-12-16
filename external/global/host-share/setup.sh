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
apt-get -qq -y install python2.7-minimal curl
bash -c "cd /tmp/host-share/sshkeys/ && python2.7 ./user_tool.py apply -j users.json -t core"

### Install java
apt -y -qq install -f
apt -y -qq install openjdk-8-jre-headless

### Setup GPG Key for logstash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
apt-get install apt-transport-https
echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
apt-get update

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

#### Install golang and docker on homebase
if grep -q homebase /etc/hostname; then
    puppet module install dp-golang --modulepath /etc/puppet/modules
    puppet module install puppetlabs-docker --modulepath /etc/puppet/modules
fi

#### Install docker on elk
if grep -q elk /etc/hostname; then
    puppet module install puppetlabs-docker --modulepath /etc/puppet/modules
fi

##### Install puppetlabs apt module
puppet module install puppetlabs-apt --modulepath /etc/puppet/modules

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
