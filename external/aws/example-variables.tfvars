# Provider initialization (tenancy, api user, key, region, etc.)

# Shared Crediental file Path
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