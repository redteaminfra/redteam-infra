# How to Play

## How to start

The first thing you'll need to do is setup IAM in AWS and generate an EC2 keypair.

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
```
From there run `source ~/.aws/awssetup.sh` before doing any deployments.

You also need to setup your AWS credentials in `~/.aws/credentials`

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

## Repo Setup

Because vagrant makes a local `.vagrant` folder to house all information about an instance, we need a copy of that repository for every VPC we need in AWS. On the chance that a change is required for the infrastructure a fork is deal.

1. git clone https://github.com/redteaminfra/redteam-infra <OPNAME>
1. Make a new repo in RedTeamInfra called <OPNAME>
1. git remote rm origin
1. git remote add origin git@github.com:redteaminfra/<OPNAME>
1. git push origin master

Once the repo is forked and cloned, you may need to make some additional modifications to the puppet modules depending on your use cases. View the README in the puppet repo for additional documentation.

## Setup Rules for VPC

You will need to configure a few select things in order to spin up homebase

1. Create a git submodule from [redteam-ssh](https://github.com/redteaminfra/redteam-ssh) that contains a valid users.json. The git submodule should be owned by you and placed in `host-share/sshkeys`. You should have at least one user with an `infra` tag. See above instructions for SSH Setup for more detail on how to do this. 
1. If using cobalt strike, plop a tarball into the puppet module in `puppet/modules/cobaltstrike/files/cobaltstrike.tgz`. If not, there are a few things you'll need to comment out such as all of the references to the `.cobaltstrike.license` in `Vagrantfile` for homebase.
1. Put a list of OPs in `external/aws/ips.py` that your company uses for OUTBOUND traffic. This will be used for both SSH inbound and OPSEC rules
1. Fill out the CIDRs in `puppet/modules/opsec/files/99-opsec` that your organization owns. These are to prevent OPSEC mistakes from homebase.
1. Add auth for AWS SMS to `puppet/modules/monitoring/files/authFile.yaml`
1. Add OUTBOUND company traffic IPs to `puppet/modules/monitoring/files/C2Compromised.yaml`
1. Add public keys to `external/sketch/provision.sh` inside the `authorized_keys` blob for users you want to access the redirector instances.

## Make a new VPC

1. `virtualenv -p python3 venv`
1. `. venv/bin/activate`
1. `pip3 install -r requirements.txt`
1. `./make_vpc.py`

## Spin up a Homebase in that VPC

Note: vagrant ssh does not work for reasons I don't fully understand.

1. `./make_boxes.sh`
1. `cd homebase`
1. `vagrant plugin install vagrant-aws`
1. `vagrant plugin install vagrant-triggers`
1. Set the VPC\_JSON env variable to point to the vpc json made above
1. Set the AWS\_KEY, AWS\_SECRET, AWS\_KEYPATH, environment variable
1. Vagrant up --provider aws

## Destroy a VPC

1. `virtualenv -p python3 venv`
1. `. venv/bin/activate`
1. `pip3 install -r requirements.txt`
1. `./backup_ebs.py -i <VPC-########> -d <description>`
1. `./del_vpc.py -j <json from make\_vpc>.json`
