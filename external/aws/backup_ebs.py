#!/usr/bin/env python3

import argparse
import boto3
import sys

def backup_vpc(vpc_id, desc):
    ec2 = boto3.resource("ec2")
    vpc = ec2.Vpc(vpc_id)
    instances = list(vpc.instances.all())
    for instance in instances:
        volume = instance.volumes.all()
        for v in volume:
            print ("[+] Snapshotting Volume " + v.id)
            try:
                snapshot = ec2.create_snapshot(VolumeId=v.id, Description=desc)
                print ("[+] Snapshot created with ID " + snapshot.id)
            except:
                a, b, c = sys.exc_info()
                print("[-] Could not create snapshot of volume: " + str(b))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Backup EBS Volumes on an AWS vpc',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument('-i', '--id', type=str, dest='vpc_id',
                        help='ID for the VPC to backup <vpc-########>',
                        required=True)

    parser.add_argument('-d', '--desc', type=str, dest='desc',
                        help='Description for Volume Snapshots',
                        required=True)

    args = parser.parse_args()
    backup_vpc(args.vpc_id, args.desc)
    sys.exit(0)
