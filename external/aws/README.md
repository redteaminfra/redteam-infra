# How to Play

## How to start

The first thing you'll need to do is set up IAM in AWS and generate an EC2 keypair.

To do so, from IAM in AWS make a user and add that user to the group "redteam".

Click on the newly created user and go to the "Security Credentials" tab. See under access and obtain the values for "AWS_KEY" and "AWS_SECRET"

You'll need to generate a PRIVATEKEY.pem file and copy it in to the ~/.aws directory.

To do so, log in to AWS and navigate to EC2. Under Network and Security select 'Key Pairs'. Select 'Create Key Pair' and use your username. It should automatically download a .pem file. Copy this .pem file to your AWS directory and rename (mv) it from your username to 'PRIVATEKEY.pem'

Source your aws setup from `~/.aws/awssetup.sh` and make it look like

```
export AWS_KEY="KEY"
export AWS_SECRET="SECRET"
export AWS_KEYNAME=USERNAME
export AWS_KEYPATH=~/.aws/PRIVATEKEY.pem
export AWS_ACCESS_KEY_ID="KEY"
export AWS_SECRET_ACCESS_KEY="SECRET"
```
From there run `source ~/.aws/awssetup.sh` before doing any deployments.

You also need to set up your AWS credentials in `~/.aws/credentials`

```
[default]
aws_access_key_id = <STUFF>
aws_secret_access_key = <THINGS>
AWS_KEY = <Same as aws_access_key_id>
AWS_SECRET=<Same as aws_secret_access_key>
```

Also set `~/.aws/config` to your zone such as

```
[default]
region=us-west-2
```

You will also need to set up a `variables.tfvars` file

```
key_name = "<Location of your key ie ~/.ssh/deploy. Note; this cannot be a password protected key>"
op_name = "<OP NAME HERE>"
aws_key_name = "<Name you will give your key in AWS>"
```

## Repo Setup

Because terraform makes a local folder to house all information about state, we need a copy of this repository for every VPC we need in AWS.

1. git clone https://github.com/redteaminfra/redteam-infra <OPNAME>
2. Make a new repo in RedTeamInfra called <OPNAME>
3. git remote rm origin
4. git remote add origin git@github.com:redteaminfra/<OPNAME>
5. git push origin master

Once the repo is forked and cloned, you may need to make some additional modifications to the puppet modules depending on your use cases. View the README in the puppet repo for additional documentation.

## What to do

In order to start an OP VPC you will need to

1. fork repo to https://github/Intel/redteam-infra/
2. change homebase to m4.4xlarge
3. change ELK to t2.large

## Setup Rules for VPC

1. Put a list of OPs in `ssh_from_company` in `main.tf` that your company uses for OUTBOUND traffic. This will be used for both SSH inbound and OPSEC rules

## Make a new VPC

1. terraform init
2. terraform apply -auto-approve -var-file=variables.tfvars

## Destroy a VPC

1. `virtualenv -p python3 venv`
2. `. venv/bin/activate`
3. `pip3 install -r requirements.txt`
4. `./backup_ebs.py -i <VPC-########> -d <description>`
5. `./del_vpc.py -i <VPC-########>`
