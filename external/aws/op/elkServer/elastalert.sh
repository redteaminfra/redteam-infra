#!/bin/bash

# pip and setuptools
apt install python-pip -y
apt install libffi-dev -y
pip install pyOpenSSL

# Clone elastalert
cd /etc/
git clone https://github.com/Yelp/elastalert.git

cd elastalert
pip install -r requirements.txt
python setup.py install

# write config
cp /tmp/config.yaml /etc/elastalert/config.yaml

# write rules
cd /etc/elastalert
mkdir rules

cp /tmp/authFile.yaml rules/authFile.yaml

cp /tmp/C2Compromised.yaml rules/C2Compromised.yaml
cp /tmp/C2Dead.yaml rules/C2Dead.yaml

systemctl restart elastalert.service
