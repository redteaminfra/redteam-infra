# How to Play

## How to start

The first thing you'll need to do is set up an Oracle Cloud account and make a compartment in your tenancy.

Copy `variables.tfvars.example` to `variables.tfvars` and modify the following variables to suit your needs:

``` terraform
# Provider initialization
# See https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/clitoken.htm for more details documentation
config_file_profile = ""

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

### config_file_profile

Can be whatever you'd like, tenancy name is recommended

Running something like: 
`oci session authenticate --profile-name CloudyCloudMcCloud --region us-ashburn-1 --tenancy-name CloudyCloudMcCloud` will launch a web browser for you to authenticate to your tenancy. It will also give you the URI you need to visit if a web-browser isn't configured to open. Use the value for `--profile-name` as the value for your `config_file_profile` variable.

From there you can run

1. `terraform init`
2. `terraform apply -var-file=variables.tfvars`

### ssh keys
SSH keys will be created and placed into ~/.ssh. They keys will be named after your engagement name, with the public key having a `.pub` extension. `ssh-config` has no bearing on the location of the keys.

### ssh-config
An SSH config will be placed into your defined `ssh_config_path` the default path is `~/.ssh`. It will be named after your engagement name

### ansible inventory
An `inventory.ini` file will be created with homebase, proxy and elk hosts and placed in `../../ansible/`

# Making Changes

## Proxy Inbound Network Rules

We define one Network Security Group (NSG) for both proxies and `network.tf` becomes the source for the rules governing the NSG. The NSG is attached to the proxy01 and proxy02 VNIC.

Terraform will cycle the VNIC when doing this attachment, so if you are applying this change to a running infra, it will cause the proxies to have new public IP.
