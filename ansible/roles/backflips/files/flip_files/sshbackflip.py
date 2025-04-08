#!/usr/bin/env python3
# Copyright (c) 2024, Oracle and/or its affiliates.

import sys
import os
import argparse
from pathlib import Path
import sshbackflip.core as bf


def init():
    # We shouldn't need to be sudo, we should instead own the backflips base directory.
    if os.getuid() != 0:
        sys.stderr.write("you must use sudo\n")
        sys.exit(1)


def parse_args():
    main_parser = argparse.ArgumentParser(prog="make_backflip", description="The SSH backlfip is a Command & Control tool that uses SSH with clever port forwarding.")

    main_parser.add_argument(
        "-v",
        "--verbose",
        help="Turn on output verbosity",
        action="store_true",
        dest='verbose'
    )

    subparsers = main_parser.add_subparsers(
        dest='scriptAction',
        title='Script action',
        help='Select which action the script should perform'
        )

    parser_newBackflip = subparsers.add_parser(
        'new',
        help='Setup a new instance of an SSH Backflip to target a new victim'
        )

    parser_newBackflip.set_defaults(func=bf.setup_backflip)

    parser_newBackflip.add_argument(
        "-b",
        "--backflipServer",
        help="You can specify a backflip server fqdn that overrides the one in the config file. Don't use this argument if you want the default from config file.",
        required=False,
        dest='backflipServer'
    )

    parser_newBackflip.add_argument(
        "-p",
        "--port",
        help="Local port on the backflip server to allocate for this backflip victim. Usually a value between 4000 and 5000.",
        required=False,
        dest='localPort'
    )

    parser_newBackflip.add_argument(
        "-u",
        "--usertarget",
        help="Username of this backflip victim. You need to know this to login to the victim host.",
        required=False,
        dest='targetUser'
    )

    parser_newBackflip.add_argument(
        "-t",
        "--targethost",
        help="Hostname of this backflip victim. This name is how we distinguish between victims.",
        required=True,
        dest='targetHost'
    )

    parser_newBackflip.add_argument(
        "-o",
        "--os",
        help='Select which operating system you want this backflip to target.',
        choices=['linux','macos','windows'],
        required=True,
        dest='targetOS'
        )

    args_linux = parser_newBackflip.add_argument_group('args_linux')

    args_linux.add_argument(
        "--python2",
        help="When this option is specified the payload will target Python2. Otherwise the default Python3.",
        default=False,
        action='store_true',
        dest='python2'
        )

    args_windows = parser_newBackflip.add_argument_group('args_windows')

    args_windows.add_argument(
        "--spoofdomain",
        help="Choose the fqdn you want to display in the SSH commands. When this backflip runs on target it will alias/spoof this name in the ssh_config",
        default="updates.microsoft.com",
        dest="spoofDomain"
    )

    args_windows.add_argument(
    "--includebins",
    help="Include the Win32-OpenSSH binaries and configuration files necessary when the victim doesn't already have Win32-OpenSSH installed. \nOtherwise just output a PowerShell script to do a backflip",
    default=False,
    action='store_true',
    dest="includeBins"
    )

    parser_connectBackflip = subparsers.add_parser(
        'connect',
        help='Connect to an existing SSH Backflip target identified by hostname'
        )

    parser_connectBackflip.set_defaults(func=bf.connect_backflip)

    parser_connectBackflip.add_argument(
        "-t",
        "--target",
        help="Hostname of the target you wish to connect to. If you don't remember check the list command",
        required=True,
        dest='targetHost'
    )

    parser_deleteBackflip = subparsers.add_parser(
        'delete',
        help='Delete an existing instance of an SSH Backflip as identified by hostname'
    )

    parser_deleteBackflip.set_defaults(func=bf.delete_backflip)

    parser_listBackflip = subparsers.add_parser(
        'list',
        help='List existing instances of SSH Backflips found in the database/configuration file'
    )

    parser_listBackflip.set_defaults(func=bf.list_backflips)

    parser_deleteBackflip.add_argument(
        "-t",
        "--targethost",
        help="Hostname of this backflip victim. This name is how we distinguish between victims.",
        required=True,
        dest='targetHost'
    )

    parser_socks = subparsers.add_parser(
    'socks',
    help='Manage the SOCKS proxy (turn on or off) for a given SSH Backflip target computer.'
    )

    parser_socks.set_defaults(func=bf.manage_socks)

    parser_socks.add_argument(
        "-t",
        "--targethost",
        help="Hostname of this backflip victim. This name is how we distinguish between victims.",
        required=True,
        dest='targetHost'
    )

    socks_toggle = parser_socks.add_mutually_exclusive_group(required=True)

    socks_toggle.add_argument(
        "-e",
        "--enable",
        help="Enable the SSH SOCKS proxy for the given backflip instance. This allows you to proxy traffic through the victim computer.",
        required=False,
        action="store_true",
        dest='socksToggle'
    )

    socks_toggle.add_argument(
        "-d",
        "--disable",
        help="Disable the SSH SOCKS proxy for the given backflip instance.",
        required=False,
        action="store_false",
        dest='socksToggle'
    )

    return main_parser.parse_args()



if __name__ == "__main__":
    init()
    args = parse_args()
    globals()['logging'] = args.verbose
    args.func(args)


    #add options to creeate a full new backfip instance VS re-creating the payload?
    #standardize printing IOCs for all payload types