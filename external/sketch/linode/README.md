# How to Play

## How to start

The first thing you'll need to do is set up a Linode account.

You will need to generate a [Linode API key](https://www.linode.com/docs/products/tools/cloud-manager/guides/cloud-api-keys/)

Next, copy `example-variables.tfvars` to  `variables.tfvars` and edit to suit your needs:

``` terraform
# Your Linode API token
linode_api_token = ""

# Which Linode region should this be built in
linode_region = ""

# Host image you would like to use
linode_image = ""

# Used for initial ssh cap from where terraform is run (ie workstation) into cloud instances
ssh_private_key = ""
ssh_public_key  = ""

# Shortname for the engagement, will be used to identify resources in Linode and hostnames
engagement_name = ""

# Path to place your ssh configuration for this infrastructure
ssh_config_path = ""
```

## Spin up Instances

From there you can run

1. `terraform init`
2. `terraform apply -var-file=variables.tfvars`
3. Run the output ansible command to configure your hosts `ansible-playbook ../ansible/sketch-playbook.yml -i inventory.ini -e "ssh_key=KEY" -e "ssh_config_path=PATH"` or use `provision.sh` to configure them manually.

## Advanced configuration

A basic configuration will allow you to setup one `middle` and one `edge` instance in your region of choice. You may use these variables in your `variables.tfvars` to change them:

### Regions
Configure different regions for your middle and edge instances.

```terraform
middle_region = "REGION-A"
edge_regions   = ["REGION-B",  "REGION-C", "REGION-D"]
```

### Instance Count
Configure multiple edge instances. (Can also be done with middle)

**NOTE:** If you have instances in multiple regions do not modify the edge count, this will have unintended consequences. 

```terraform
edge_count = "N"
```

### Instance Type
Can be done with both middle and edge instances.

```terraform
middle_type = "g6-nanode-1"
```