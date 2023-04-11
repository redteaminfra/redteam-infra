# How to Play

## How to start

The first thing you'll need to do is set up IAM in AWS and generate an EC2 keypair.

To do so, from IAM in AWS make a user and add that user to the group "redteam".

Click on the newly created user and go to the "Security Credentials" tab. See under access and obtain the values for "AWS_KEY" and "AWS_SECRET"

You'll need to generate a PRIVATEKEY.pem file and copy it in to the ~/.aws directory.

To do so, log in to AWS and navigate to EC2. Under Network and Security select 'Key Pairs'. Select 'Create Key Pair' and use your username. It should automatically download a .pem file. Copy this .pem file to your AWS directory and rename (mv) it from your username to 'PRIVATEKEY.pem'



You also need to put your AWS credentials in `~/.aws/credentials`

```
[default]
aws_access_key_id = <STUFF>
aws_secret_access_key = <THINGS>
```

Also set `~/.aws/config` to your zone such as

```
[default]
region=us-west-2
```

You will also need to set up a `variables.tfvars` file see the `example-variables.tfvars` for an example.

``` terraform
# Provider initialization (tenancy, api user, key, region, etc.)
shared_credentials_file = "~/.aws/credentials"



# Optional, default path is `~/.ssh`
#ssh_config_path              = ""

#Key Pair for sshing to hosts
key_name = "~/.ssh/id_rsa"
public_key = "~/.ssh/id_rsa.pub"

# Which region
aws_key_name = ""
# use the Region Identifier, e.g: us-west-2
region         = "us-west-2"
# Which availability zone
availability_zone      = "us-west-2a"

# The engagement's name, infrastructure will be named after this
engagement_name = "test"

#"dev" = "t3.medium"
#"prod" = "t3.large"
# define the shape for homebase
homebase_shape = "t3.medium"
# define the shape for proxies
proxy_shape    = "t3.medium"
proxy_count    = 2
# define the shape for elk
elk_shape      = "t3.medium"

# Set to IP's and/or IP ranges you would like to have SSH access to the infrastructure
# Each item in range should be an address range in cidr formate
# e.g. ssh_allowed_cidr_ranges = ["192.168.32.0/25", "172.16.0.0/16"]
ssh_allowed_cidr_ranges = [""]
```

## What to do

In order to start an OP VPC you will need to

1. fork repo to https://github.com/redteaminfra/redteam-infra
2. change homebase to m4.4xlarge
3. change ELK to t2.large

## Make a new VPC

1. `terraform init`
2. `terraform apply -auto-approve -var-file=variables.tfvars`

## Destroy a VPC

1. `terraform destroy -var-file=variables.tfvars`


### ssh-config
An SSH config will be placed into your defined `ssh_config_path` the default path is `~/.ssh`. It will be named after your engagement name

### ansible inventory
An `inventory.ini` file will be created with homebase, proxy and elk hosts and placed in `../../ansible/`
Inside the `ansible/site.yaml uncomment the aws role to ensure that the VPC DNS resolver is blocked.

# Making Changes

## Proxy Inbound Network Rules

We define one Network Security Group (NSG) for both proxies and `network.tf` becomes the source for the rules governing the NSG. The NSG is attached to the proxy01 and proxy02 VNIC.

Terraform will cycle the VNIC when doing this attachment, so if you are applying this change to a running infra, it will cause the proxies to have new public IP.
