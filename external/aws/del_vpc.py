#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import boto3
import argparse
import json
import time
import os

def find_vpc_from_json(filename):
    with open(filename, "r") as f:
        jsonblob = f.read()
        j = json.loads(jsonblob)
        name = list(j.keys())[0]
        v = j[name]
        vpc_id = v["vpc_id"]
        print("[+] vpc id:", vpc_id)
        return vpc_id

def del_vpc(vpc_id, filename):
    # following the plan at
    #  https://gist.github.com/neilswinton/d37787a8d84387c591ff365594bd26ed
    ec2 = boto3.resource('ec2')
    vpc = ec2.Vpc(vpc_id)
    vpc.load()

    num_instances = len(list(vpc.instances.all()))
    print("[+] detected %d instances in the vpc" % num_instances)
    if num_instances > 0:
        print("[-] refusing to delete non-empty vpc");
        sys.exit(1)

    print("[+] finding security groups")
    security_groups = vpc.security_groups.all()
    for sec_group in security_groups:
        if sec_group.description == "default VPC security group":
            continue
        print("[+] deleting security group", sec_group.id)
        sec_group.delete()

    print("[+] finding subnets")
    for subnet in vpc.subnets.all():
        print("[+] deleting subnet:", subnet.id)
        subnet.delete()
    print("[+] finding routes")
    for route_table in vpc.route_tables.all():
        for route in route_table.routes_attribute:
            if route['Origin'] == 'CreateRoute':
                print("[+] deleting route:", route)
                client = boto3.client('ec2')
                client.delete_route(
                    DestinationCidrBlock = route["DestinationCidrBlock"],
                    RouteTableId = route_table.id
                )
        try:
            print("[+] deleting route table:", route_table.id)
            route_table.delete()
        except:
            print("[-] got an error, but continuing anyways")
            pass
    print("[+] finding acls")
    for acl in vpc.network_acls.all():
        if not acl.is_default:
            print("[+] deleting network acl:", acl.id)
            acl.delete()
    print("[+] finding network interfaces")
    for subnet in vpc.subnets.all():
        for network_interface in subnet.network_interfaces.all():
            print("[+] deleting network interface:", network_interfac.id)
            network_interface.delete()
    print("[+] finding internet gateways")
    for internet_gateway in vpc.internet_gateways.all():
        print("[+] deleting internet gateway:", internet_gateway.id)
        internet_gateway.detach_from_vpc(VpcId = vpc_id)
        internet_gateway.delete()
    vpc.delete()
    if filename:
        os.remove(filename)
        print("[+] deleting vpc json file:", filename)
    print("[+] done")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Destroy an AWS vpc.',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-j', '--json', type=str, dest='json',
                        help='JSON file to read vpc-id from')
    group.add_argument('-i', '--vpc_id', type=str, dest='vpc_id',
                       help='id of the VPC')
    args = parser.parse_args()
    vpc_id = None
    if args.json:
        vpc_id = find_vpc_from_json(args.json)

    if args.vpc_id:
        vpc_id = args.vpc_id
        print("[+] vpc id:", vpc_id)


    print("\n")
    print("{:*^80s}".format("  WARNING  "))
    print("{: ^80s}".format("This is your chance to hit ctrl-c before deletion"))
    time.sleep(3)
    print("{:*^80s}".format("  CONTINUING  "))
    print("\n")

    del_vpc(vpc_id, args.json)

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
