# How to Play

## How to start

The first thing you'll need to do is set up an Oracle Cloud account, generate a key pair, and make a compartment in your tenancy.

You will need to add information regarding your tenancy to `~/.oci/config` such as

```
[DEFAULT]
user=< USER OCID HERE >
fingerprint=< FINGERPRINT HERE >
key_file=< KEY HERE >
tenancy=< TENANCY OCID HERE >
region=< REGION HERE >
```

Copy `example-variables.tfvars` to `variables.tfvars` and modify the following variables to suit your needs:

``` terraform
# Provider initialization (tenancy, api user, key, region, etc.)
tenancy_ocid     = ""
user_ocid        = ""
fingerprint      = ""
private_key_path = ""

# Used for initial ssh cap from where terraform is run (ie workstation) into cloud instances
ssh_provisioning_private_key = ""
ssh_provisioning_public_key  = ""

# Optional, default path is `~/.ssh`
# ssh_config_path              = ""

# Which compartment the infra be setup in:
compartment_id = ""

# Which region
# https://docs.oracle.com/en-us/iaas/Content/General/Concepts/regions.htm
# use the Region Identifier, e.g: us-sanjose-1
region         = ""
# Which availability domain
ad_number      = "1"

# The engagement's name, infrastructure will be named after this
engagement_name = ""

# define the shape for homebase
homebase_shape = "VM.Standard2.1"
# define the shape for proxies
proxy_shape    = "VM.Standard2.1"
proxy_count    = 2
# define the shape for elk
elk_shape      = "VM.Standard2.1"

# Set to IP's and/or IP ranges you would like to have SSH access to the infrastructure
# Each item in range should be an address range in cidr formate
# e.g. ssh_allowed_cidr_ranges = ["192.168.32.0/25", "172.16.0.0/16"]
ssh_allowed_cidr_ranges = []
```

## Spin up Instances

From there you can run

1. `terraform init`
2. `terraform apply -var-file=variables.tfvars`

### ssh-config
An SSH config will be placed into your defined `ssh_config_path` the default path is `~/.ssh`. It will be named after your engagement name

# Making Changes

## Proxy Inbound Network Rules

We define one Network Security Group (NSG) for both proxies and `network.tf` becomes the source for the rules governing the NSG. The NSG is attached to the proxy01 and proxy02 VNIC.

Terraform will cycle the VNIC when doing this attachment, so if you are applying this change to a running infra, it will cause the proxies to have new public IP.
