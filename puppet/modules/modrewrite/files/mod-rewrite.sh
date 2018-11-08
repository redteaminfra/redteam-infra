#!/usr/bin/bash

cd /opt/modrewrite

VPC=$(hostname | /usr/bin/cut -d '-' -f2- | tr -d '\n')
server="homebase-$VPC.infra.us"

/usr/bin/python apache_redirector_setup.py --malleable="/opt/malleable/amazon.profile" --block_url="http://127.0.0.1" --block_mode="redirect" --allow_url="http://$server" --allow_mode="proxy" --mobile_url="http://127.0.0.1" --mobile_mode="redirect" --backup --silent

systemctl restart apache2
