#!/bin/bash

# export noninteractive install
export DEBIAN_FRONTEND=noninteractive

# remove copied over proxy crap
rm /etc/environment && touch /etc/environment
if [ -e /etc/profile.d/proxy.sh ] ; then
    rm /etc/profile.d/proxy.sh
    rm /etc/apt/apt.conf.d/01proxy
fi
unset http_proxy
unset https_proxy
unset no_proxy
unset NO_PROXY
unset HTTP_PROXY
unset HTTPS_PROXY

### Disable apt timer
systemctl disable apt-daily.timer

### Update package database
apt-get update

### I hate everything 🖕
sleep 3m

### Install puppet
regex="Version: ([0-9])\.([0-9])\.([0-9]).*"
if [[ `apt-cache show puppet` =~ $regex ]] && [[ ${BASH_REMATCH[1]} -lt 4 ]]
then
   cd ~ && wget https://apt.puppetlabs.com/puppetlabs-release-pc1-trusty.deb
   sudo dpkg -i puppetlabs-release-pc1-trusty.deb
   sudo apt-get update
   sudo apt-get -y install puppet-agent || exit 1
   ln -s /opt/puppetlabs/bin/puppet /usr/bin/puppet
else
   apt-get -y install puppet  || exit 1
fi

puppet module install elastic-logstash --version 5.1.0 --modulepath "/etc/puppet/modules"
puppet module install puppetlabs-apt --version 4.3.0 --modulepath "/etc/puppet/modules"

### Install git
apt-get install -y git

### user setup
apt-get -y install python-minimal
bash -c "cd /tmp/host-share/sshkeys/ && ./user_tool.py apply -j users.json -t volunteer -t core"

### fix vagrant provision
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

### ssh fixes
sed -i -e 's/UsePAM yes/UsePAM no/' /etc/ssh/sshd_config
sed -i -e 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
/etc/init.d/ssh reload

### disable ipv6
cat <<EOF >> /etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
sysctl -p

### bootstrap puppet env
echo "vpc=$(/bin/bash -c /bin/hostname | /usr/bin/cut -d '-' -f2- | tr -d '\n')" >> /etc/profile.d/puppet.sh
echo "subnet=$(hostname -I | cut -d. -f1-3)" >> /etc/profile.d/puppet.sh
