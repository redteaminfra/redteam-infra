#!/bin/bash
# Copyright (c) 2023, Oracle and/or its affiliates.


if [ $(whoami) != "root" ]; then
    echo "you must be root"
    exit 1
fi

if [[ -z $1 ]];
then
    echo "./provision.sh <hostname>"
    echo "Example: ./provision.sh edge-sketch5"
    exit 1
fi

HOSTNAME=$1

hostnamectl set-hostname $HOSTNAME

# Disable IPV6 for reals
cat << EOF >> /etc/default/grub.d/99-disable-ipv6.cfg
GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT ipv6.disable=1"
EOF
update-grub

export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get -y install screen tmux ufw nginx simpleproxy python

useradd -p '*' -m -s '/bin/bash' -k /etc/skel  user
mkdir ~user/.ssh
cat <<EOF > ~user/.ssh/authorized_keys
<YOUR AUTHORIZED KEYS HERE>
EOF
chmod 700 ~user/.ssh
chmod 600 ~user/.ssh/authorized_keys
chown -R user:user ~user

sed -i -E 's/#?PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i -E 's/#?UsePAM yes/UsePAM no/' /etc/ssh/sshd_config
sed -i -E 's/#?ChallengeResponseAuthentication yes/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config

echo "sshd config:"
grep -i PasswordAuthentication /etc/ssh/sshd_config
grep -i UsePAM /etc/ssh/sshd_config
grep -i ChallengeResponseAuthentication /etc/ssh/sshd_config

cat <<EOF > /etc/sudoers.d/99user
user            ALL = (ALL) NOPASSWD: ALL
EOF
chmod 440 /etc/sudoers.d/99user

/etc/init.d/ssh reload
ufw allow ssh
ufw allow http
ufw allow https
ufw allow 2222/tcp
ufw --force enable
apt-get -y install unattended-upgrades

useradd -s /bin/bash -d /home/sketchssh -m sketchssh
usermod -p '*' sketchssh
usermod -U sketchssh
