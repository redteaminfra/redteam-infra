#!/usr/bin/env python3
# Copyright (c) 2024, Oracle and/or its affiliates.

import sys
import os
import argparse
from pathlib import Path
import sshbackflip.core as core


def init():
    # We shouldn't need to be sudo, we should instead own the backflips base directory.
    if os.getuid() != 0:
        sys.stderr.write("you must use sudo\n")
        sys.exit(1)


def add_common_arguments(parser):
    """Add arguments that are common across multiple subcommands."""
    parser.add_argument(
        "-t", "--target",
        help="Hostname of the backflip victim (used to distinguish between victims)",
        required=True,
        dest='targetHost'
    )


def create_backflip_new_parser(subparsers):
    """Create the parser for the 'backflip new' subcommand."""
    parser = subparsers.add_parser(
        'new',
        help='Setup a new instance of an SSH Backflip to target a new victim'
    )
    parser.set_defaults(func=core.setup_backflip)

    # Required arguments
    add_common_arguments(parser)
    parser.add_argument(
        "-o", "--os",
        help='Select which operating system you want this backflip to target',
        choices=['linux', 'macos', 'windows'],
        required=True,
        dest='targetOS'
    )

    # Optional arguments
    parser.add_argument(
        "-b", "--backflip-server",
        help="Backflip server for callbacks (defaults to value from etc/backflips.conf)",
        dest='backflipServer'
    )
    parser.add_argument(
        "-p", "--port",
        help="Local port on the backflip server (typically 4000-5000)",
        dest='localPort'
    )
    parser.add_argument(
        "-u", "--user",
        help="Username of the backflip victim",
        dest='targetUser'
    )

    # OS-specific argument groups
    linux_group = parser.add_argument_group('Linux Options')
    linux_group.add_argument(
        "--python2",
        help="Target Python 2 instead of Python 3",
        action='store_true',
        dest='python2'
    )

    windows_group = parser.add_argument_group('Windows Options')
    windows_group.add_argument(
        "--spoof-domain",
        help="FQDN to display in SSH commands (for config spoofing)",
        default="updates.microsoft.com",
        dest="spoofDomain"
    )
    windows_group.add_argument(
        "--include-bins",
        help="Include Win32-OpenSSH binaries and config files",
        action='store_true',
        dest="includeBins"
    )

    return parser


def create_backflip_connect_parser(subparsers):
    """Create the parser for the 'backflip connect' subcommand."""
    parser = subparsers.add_parser(
        'connect',
        help='Connect to an existing SSH Backflip target'
    )
    parser.set_defaults(func=core.connect_backflip)
    add_common_arguments(parser)
    return parser


def create_backflip_delete_parser(subparsers):
    """Create the parser for the 'backflip delete' subcommand."""
    parser = subparsers.add_parser(
        'delete',
        help='Delete an existing SSH Backflip instance'
    )
    parser.set_defaults(func=core.delete_backflip)
    add_common_arguments(parser)
    return parser


def create_backflip_list_parser(subparsers):
    """Create the parser for the 'backflip list' subcommand."""
    parser = subparsers.add_parser(
        'list',
        help='List existing SSH Backflip instances'
    )
    parser.set_defaults(func=core.list_backflips)
    return parser


def create_backflip_socks_parser(subparsers):
    """Create the parser for the 'backflip socks' subcommand."""
    parser = subparsers.add_parser(
        'socks',
        help='Manage SOCKS proxy for a backflip target'
    )
    parser.set_defaults(func=core.manage_socks)
    add_common_arguments(parser)

    socks_toggle = parser.add_mutually_exclusive_group(required=True)
    socks_toggle.add_argument(
        "-e", "--enable",
        help="Enable SSH SOCKS proxy for traffic proxying",
        action="store_true",
        dest='socksToggle'
    )
    socks_toggle.add_argument(
        "-d", "--disable",
        help="Disable SSH SOCKS proxy",
        action="store_false",
        dest='socksToggle'
    )
    return parser


def create_backflip_check_faceplant_parser(subparsers):
    """Create the parser for the 'backflip check-faceplant' subcommand."""
    parser = subparsers.add_parser(
        'check-faceplant',
        help='Check SSH logs for faceplant leaks and update victim usernames'
    )
    parser.set_defaults(func=core.check_faceplant)
    parser.add_argument(
        "-d", "--date",
        help="Start date for log search (YYYY-MM-DD format, defaults to today)",
        dest='searchDate'
    )
    return parser


def create_backflip_parser(subparsers):
    """Create the parser for the 'backflip' command and its subcommands."""
    parser = subparsers.add_parser(
        'backflip',
        help='Manage SSH Backflip instances and connections'
    )

    # Create subparsers for backflip commands
    backflip_subparsers = parser.add_subparsers(
        dest='backflipAction',
        title='Backflip Commands',
        help='Available backflip operations'
    )

    # Create all backflip subcommand parsers
    create_backflip_new_parser(backflip_subparsers)
    create_backflip_connect_parser(backflip_subparsers)
    create_backflip_delete_parser(backflip_subparsers)
    create_backflip_list_parser(backflip_subparsers)
    create_backflip_socks_parser(backflip_subparsers)
    create_backflip_check_faceplant_parser(backflip_subparsers)

    return parser


def create_listener_parser(subparsers):
    """Create the parser for the 'listener' command."""
    parser = subparsers.add_parser(
        'listener',
        help='Manage backflip listener registry'
    )
    parser.set_defaults(func=core.manage_servers)

    listener_subparsers = parser.add_subparsers(dest="serverAction")

    # Add listener subcommand
    add_parser = listener_subparsers.add_parser("add", help="Add a new C2 endpoint")
    add_parser.add_argument("-n", "--name", required=True, dest='name',
                          help="Friendly name for the listener")
    add_parser.add_argument("-c", "--callback-host", dest='callbackHost',
                          help="Public IP/FQDN for victim callbacks")
    add_parser.add_argument("-i", "--internal-ip", dest='internalIP',
                          help="Internal IP for operator connections (default: localhost)")
    add_parser.add_argument("-p", "--port", dest='callbackPort',
                          help="Callback port (default: 2222)")
    add_parser.add_argument("-u", "--user", dest='callbackUser',
                          help="Callback username (default: flip)")

    # Delete listener subcommand
    del_parser = listener_subparsers.add_parser("delete", help="Delete a C2 endpoint")
    del_parser.add_argument("-n", "--name", required=True, dest='name',
                         help="Friendly name for the listener")

    # Other listener subcommands
    listener_subparsers.add_parser("reconcile",
                                help="Update backflips.conf with ip_mapping.json")
    listener_subparsers.add_parser("list",
                                help="List configured C2 endpoints")

    return parser


def parse_args():
    """Parse and return command line arguments."""
    parser = argparse.ArgumentParser(
        prog="sshbackflip.py",
        description="SSHbackflip - Simplify SSH-based Command & Control"
    )

    parser.add_argument(
        "-v", "--verbose",
        help="Enable verbose output",
        action="store_true",
        dest='verbose'
    )

    subparsers = parser.add_subparsers(
        dest='command',
        title='Available Commands',
        help='Select a command to perform'
    )

    # Create main command parsers
    create_backflip_parser(subparsers)
    create_listener_parser(subparsers)

    return parser.parse_args()


if __name__ == "__main__":
    init()
    args = parse_args()
    globals()['logging'] = args.verbose
    if hasattr(args, "func"):
        args.func(args)


    #add options to creeate a full new backfip instance VS re-creating the payload?
    #standardize printing IOCs for all payload types