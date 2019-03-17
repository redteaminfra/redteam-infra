#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import boto3
import argparse
import random
import json
import time
from ips import COMPANY_OUTBOUND

VPC_CIDR = '192.168.0.0/16'
DEFAULT_REGION = 'us-west-2'

vpc_info = {}

class VPC:
    def __init__(self, ec2, vpc_id, **kwargs):
        self.ec2 = ec2
        self.vpc_id = vpc_id
        for key, value in kwargs.items():
            if key == "name":
                self.name = value
            elif key == "desc":
                self.desc = value
            elif key == "perms":
                self.perms = value
            else:
                raise ValueError

    def make_vpc(self):
        vpc_security = self.ec2.create_security_group(GroupName=self.name,
                                                      Description = self.desc,
                                                      VpcId = self.vpc_id)
        time.sleep(0.5) # AWS seems to unrealiably make security groups without the sleep 🖕
        vpc_security.create_tags(
            Tags=[{
                'Key' : 'Name',
                'Value' : self.desc
            }])
        vpc_ingress = vpc_security.authorize_ingress(
            GroupId = vpc_security.id,
            IpPermissions = self.perms
        )

        friendly_name = self.name.replace("_", " ")
        print('[+] Security Group Created for %s' % friendly_name, vpc_security.id)
        return vpc_security


def make_ssh_security(ec2, vpc_id):
    vpc = VPC(ec2, vpc_id,
              name = 'SSH_From_COMPANY',
              desc = 'SSH From COMPANY',
              perms = [
                  {
                      'IpProtocol' : 'tcp',
                      'FromPort' : 22,
                      'ToPort' : 22,
                      'IpRanges' : COMPANY_OUTBOUND
                  }
              ])
    return vpc.make_vpc()

def make_http_security(ec2, vpc_id):
    vpc = VPC(ec2, vpc_id,
              name = 'HTTP_From_COMPANY',
              desc ='HTTP From COMPANY',
              perms = [
                  {
                      'IpProtocol' : 'tcp',
                      'FromPort' : 80,
                      'ToPort' : 80,
                      'IpRanges' : COMPANY_OUTBOUND
                  }
              ])
    return vpc.make_vpc()

def make_https_security(ec2, vpc_id):
    vpc = VPC(ec2, vpc_id,
              name = 'HTTPS_From_Company',
              desc ='HTTPS From Company',
              perms = [
                  {
                      'IpProtocol' : 'tcp',
                      'FromPort' : 443,
                      'ToPort' : 443,
                      'IpRanges' : COMPANY_OUTBOUND
                  }
              ])
    return vpc.make_vpc()

def make_http_security_anywhere(ec2, vpc_id):
    vpc = VPC(ec2, vpc_id,
              name = 'HTTP_From_Anywhere',
              desc ='HTTP From Anywhere',
              perms = [
                  {
                      'IpProtocol' : 'tcp',
                      'FromPort' : 80,
                      'ToPort' : 80,
                      'IpRanges' : [{'CidrIp' : '0.0.0.0/0'}]
                  }
              ])
    return vpc.make_vpc()

def make_https_security_anywhere(ec2, vpc_id):
    vpc = VPC(ec2, vpc_id,
              name = 'HTTPS_From_Anywhere',
              desc ='HTTPS From Anywhere',
              perms = [
                  {
                      'IpProtocol' : 'tcp',
                      'FromPort' : 443,
                      'ToPort' : 443,
                      'IpRanges' : [{'CidrIp' : '0.0.0.0/0'}]
                  }
              ])
    return vpc.make_vpc()

def make_dns_security(ec2, vpc_id):
    vpc = VPC(ec2, vpc_id,
              name = 'DNS_From_World',
              desc = 'DNS from World',
              perms = [
                  {
                      'IpProtocol' : 'tcp',
                      'FromPort' : 53,
                      'ToPort' : 53,
                      'IpRanges' : [{'CidrIp' : '0.0.0.0/0'}]
                  },
                  {
                      'IpProtocol' : 'udp',
                      'FromPort' : 53,
                      'ToPort' : 53,
                      'IpRanges' : [{'CidrIp' : '0.0.0.0/0'}]
                  }
              ])
    return vpc.make_vpc()

def make_4444_security(ec2, vpc_id):
    vpc = VPC(ec2, vpc_id,
              name = '4444_From_Company',
              desc = '4444 From Company',
              perms = [
                  {
                      'IpProtocol' : 'tcp',
                      'FromPort' : 4444,
                      'ToPort' : 4444,
                      'IpRanges' : COMPANY_OUTBOUND
                  }
        ])
    return vpc.make_vpc()

def make_2222_from_world(ec2, vpc_id):
    vpc = VPC(ec2, vpc_id,
              name = '2222_From_Anywhere',
              desc = '2222 From Anywhere',
              perms = [
                  {
                      'IpProtocol' : 'tcp',
                      'FromPort' : 2222,
                      'ToPort' : 2222,
                      'IpRanges' : [{'CidrIp' : '0.0.0.0/0'}]
                  }
        ])
    return vpc.make_vpc()

def make_vpc_allow_all(ec2, vpc_id):
    vpc = VPC(ec2, vpc_id,
              name = 'vpc_allow_all',
              desc = 'VPC Allow all traffic',
              perms = [
                  {
                      'IpProtocol' : 'tcp',
                      'FromPort' : 0,
                      'ToPort' : 65535,
                      'IpRanges' : [{'CidrIp' : '192.168.1.0/24'}]
                  },
                  {
                      'IpProtocol' : 'udp',
                      'FromPort' : 0,
                      'ToPort' : 65535,
                      'IpRanges' : [{'CidrIp' : '192.168.1.0/24'}]
                  }
              ])
    return vpc.make_vpc()

def make_vpc(region, vpc_name):
    ec2 = boto3.resource(service_name='ec2', region_name=region)
    vpc_info[vpc_name] = {}
    vpc_info[vpc_name]['region'] = region

    # Create VPC
    vpc = ec2.create_vpc(CidrBlock=VPC_CIDR)

    vpc.create_tags(
        Tags=[{
            'Key' : 'Name',
            'Value' : vpc_name
        }])

    print('[+] VPC Created:', vpc.id)
    vpc_info[vpc_name]['vpc_id'] = vpc.id

    # Create a routing table & route to the internet

    ig = ec2.create_internet_gateway()
    vpc.attach_internet_gateway(InternetGatewayId=ig.id)
    routing = vpc.create_route_table()
    routing.create_route(DestinationCidrBlock='0.0.0.0/0', GatewayId=ig.id)

    print('[+] Routing Table created', routing.id)
    vpc_info[vpc_name]['routing_id'] = routing.id

    # Create Subnets
    subnet = ec2.create_subnet(CidrBlock='192.168.1.0/24', VpcId=vpc.id)
    routing.associate_with_subnet(SubnetId=subnet.id)

    print('[+] Subnet created', subnet.id)
    vpc_info[vpc_name]['subnet_id'] = subnet.id


    ssh_security = make_ssh_security(ec2, vpc.id)
    http_security = make_http_security(ec2, vpc.id)
    https_security = make_https_security(ec2, vpc.id)
    http_security_anywhere = make_http_security_anywhere(ec2, vpc.id)
    https_security_anywhere = make_https_security_anywhere(ec2, vpc.id)
    dns_security = make_dns_security(ec2, vpc.id)
    four444_security = make_4444_security(ec2, vpc.id)
    vpc_allow_all = make_vpc_allow_all(ec2, vpc.id)

    vpc_info[vpc_name]['security_groups'] = {
        ssh_security.tags[0]["Value"] : ssh_security.id, # 🖕
        http_security.tags[0]["Value"] : http_security.id, # 🖕
        https_security.tags[0]["Value"] : https_security.id, # 🖕
        http_security_anywhere.tags[0]["Value"] : http_security_anywhere.id, # 🖕
        https_security_anywhere.tags[0]["Value"] : https_security_anywhere.id, # 🖕
        dns_security.tags[0]["Value"] : dns_security.id, # 🖕
        four444_security.tags[0]["Value"] : four444_security.id, # 🖕
        vpc_allow_all.tags[0]["Value"] : vpc_allow_all.id # 🖕
    }


    json_file = vpc_name + '-' + vpc.id + '.json'
    print('[+] Saving JSON data to', json_file)
    with open(json_file, 'w') as f:
        f.write(json.dumps(vpc_info, indent=4))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Make a new AWS vpc',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-r', '--region', type=str, dest='region',
                        default=DEFAULT_REGION,
                        help='AWS region to use')
    parser.add_argument('-n', '--name', type=str, dest='name',
                        default="UNAMED-VPC-%d" % random.randrange(1, 1000, 1),
                        help='name for this VPC')

    args = parser.parse_args()
    make_vpc(args.region, args.name)
    sys.exit(0)


#
# Editor modelines  -  https://www.wireshark.org/tools/modelines.html
#
# Local variables:
# c-basic-offset: 4
# indent-tabs-mode: nil
# End:
#
# vi: set shiftwidth=4 expandtab:
# :indentSize=4:noTabs=true:
#
