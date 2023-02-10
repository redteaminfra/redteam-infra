# Copyright (c) 2023, Oracle and/or its affiliates.

# Provider initialization (tenancy, api user, key, region, etc.)
tenancy_ocid     = ""
user_ocid        = ""
fingerprint      = ""
private_key_path = ""

# Used for initial ssh cap from where terraform is run (ie workstation) into cloud instances
ssh_provisioning_private_key = ""
ssh_provisioning_public_key  = ""

# Optional, default path is `~/.ssh`
#ssh_config_path              = ""

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