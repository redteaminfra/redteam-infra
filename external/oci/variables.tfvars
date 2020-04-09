# Provider initialization (tenancy, api user, key, region, etc.)
tenancy_ocid=""
user_ocid=""
oci_api_fingerprint=""
oci_api_private_key_path=""
region=""


# What compartment should the infra be setup in
compartment_id=""

# Used for initial ssh cap from where terraform is run (ie workstation) into cloud instances
ssh_provisioning_private_key=""
ssh_provisioning_public_key=""

op_name=""

# Adjust this to false for prod operation infrastructure
preserve_boot_volume = "false"
