#!/bin/bash

# Provisioning script if needed or wanted. Not necessary to use just something to automate a few steps.

echo "Provisioning OCI resources..."
cd /path/to/oci/terraform
terraform init
terraform apply -var-file=variables.tfvars -auto-approve

echo "Configuring OCI resources..."
cd ../../ansible && ansible-playbook -i inventory.ini site.yml


echo "Provisioning Sketch resources..."
cd /path/to/do/terraform
terraform init
terraform apply -var-file=variables.tfvars -auto-approve

echo "Configuring Sketch resources..."
ansible-playbook ../ansible/sketch-playbook.yml -i inventory.ini -e "ssh_pub_key=/home/user/.ssh/user-dev.pub" -e "ssh_config_path=/home/user/.ssh/redteam-sshconfigs/configs/user-dev-sketch"

# Step 3: Trigger additional OCI configuration
echo "Running additional OCI configuration..."
cd /path/to/playbook
ansible-playbook -i inventory.ini openresty-proxy-pb.yml

echo "Automation complete!"
