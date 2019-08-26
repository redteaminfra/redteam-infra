# How to Play

## How to start

The first thing you'll need to do is setup an Oracle Cloud account, generate a key pair, and make a compartment in your tenancy.

You will need to add information reguarding your tenancy to `~/.oci/config` such as

```
[DEFAULT]
user=< USER OCID HERE >
fingerprint=< FINGERPRINT HERE >
key_file=< KEY HERE >
tenancy=< TENANCY OCID HERE >
region=<REGION HERE >
```

You'll also want to define the following variables in `variables.tfvars`:

```
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
```

## Setup Rules For OCI

1. Put a list of IPs in `external/oci/seclists.json` in the `ssh_from_compnay` tag that your company uses for OUTBOUND traffic. This will be used for both SSH inbound and OPSEC rules

## Spin up Instances

From there you can run

1. `make`
1. `terraform init`
1. `terraform apply -var-file=variables.tfvars`

# Making Changes

## Proxy Inbound Network Rules

We define one Network Security Group (NSG) for both proxies and
`network_security_group.tf` becomes the source for the rules governing
the NSG. The NSG is attached to the proxy1 and proxy2 VNIC.

Terraform will cycle the VNIC when doing this attachment, so if you
are applying this change to a running infra, it will cause the proxies
to have new public IP
