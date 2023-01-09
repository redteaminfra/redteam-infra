#!/usr/bin/env python3
# Copyright (c) 2023, Oracle and/or its affiliates.

import json
import sys
import argparse
import tempfile
import os
import subprocess
import difflib
import shutil

# jsonschema isn't in the default lib, try to import it. If it isn't there tell the user
try:
    from jsonschema import validate, FormatChecker
except ImportError:
    print('jsonschema module is not installed.')
    print('pip3 install jsonschema')
    sys.exit(1)

schema = {
    "$schema": "http://json-schema.org/draft-04/schema#",
    "type": "object",
    "patternProperties": {
        "proxy*": {
            "items": [
                {
                    "type": "object",
                    "properties": {
                        "middle": {
                            "format": "ipv4"
                        },
                        "edges": {
                            "type": "array",
                            "items":
                            {
                                "format": "ipv4"
                            }
                        }
                    },
                    "required": [
                        "middle",
                        "edges"
                    ]
                }
            ]
        }
    }
}

# Print the SSH Stanzas we will use for an engagement to connect to sketch infra
StanzaTemplate = """
Host %(location)s-%(number)d-sketch-%(engagementName)s
    Hostname %(ip)s
    ProxyJump %(proxyName)s-%(engagementName)s
    IdentityFile ~/.ssh/sketchKey
    User root
"""


def parse_args():
    parser_desc = "Sketch JSON Configuration."
    parser = argparse.ArgumentParser(
        prog="sketchJSON", description=parser_desc)
    parser.add_argument(
        "-j",
        "--json",
        help="The json data for your sketch config",
        required=True,
        dest='sketchJSON'
    )
    parser.add_argument(
        "-s",
        "--ssh",
        action='store_true',
        help="Print SSH Stanza usage for sketch",
        dest='ssh'
    )
    parser.add_argument(
        "-n",
        "--name",
        help="Name of the engagement",
        dest='name'
    )
    parser.add_argument(
        "-g",
        "--graph",
        action='store_true',
        help="Make a png graph for confluence. Requires `dot`",
        dest='graph'
    )
    parser.add_argument(
        "-c",
        "--conflu",
        action='store_true',
        help="Make a markup table for confluence",
        dest='conflu'
    )
    parser.add_argument(
        "-p",
        "--puppet",
        help="Path to the sketch.json used with puppet. This will be in an <infra>/puppet/modules/sketchopsec/files/sketch.json",
        dest='puppet'
    )
    args = parser.parse_args()

    return args


def slurp_json(filename):
    contents = None
    with open(filename) as f:
        contents = f.read()
    obj = json.loads(contents)

    # Validate the incoming json object against our schema
    validateJson(obj)
    return obj


def obj_to_conflu(obj):
    conflu = "||Proxy|||Middle|||Edge||\n"
    for k, v in obj.items():
        for group in v:
            middle_ip = group["middle"]
            for edge in group["edges"]:
                conflu += f"|{k}|{middle_ip}|{edge}|\n"
    return conflu


def obj_to_dot(obj):
    def ts(x): return f"\t{x};\n"
    def q(x): return f"\"{x}\""

    dot = "digraph G {\n"
    edges = []
    for k, v in obj.items():
        dot += ts(q(k))

        for group in v:
            middle_ip = group["middle"]
            dot += ts(q(middle_ip))
            edges.append(ts(f"{q(k)} -> {q(middle_ip)}"))
            for edge in group["edges"]:
                dot += ts(q(edge))
                edges.append(ts(f"{q(middle_ip)} -> {q(edge)}"))
    dot += "\n"
    for edge in edges:
        dot += edge
    dot += "}\n"
    return dot


def run_dot(dot, outputfilename):
    # check to see if the `dot` command is in the users path
    if shutil.which('dot') is None:
        print("The dot command doesn't exit in your path. Do you have graphviz installed?")
        sys.exit(1)

    with tempfile.TemporaryDirectory() as tmpdirname:
        dotfilename = os.path.join(tmpdirname, "dot.dot")
        pngfilename = outputfilename
        with open(dotfilename, "w") as f:
            f.write(dot)
        args = ["dot", "-Tpng", "-o", pngfilename, dotfilename]
        subprocess.run(args, check=True)


def printStanza(jsonObject, engagementName):

    midTracker = 1
    endgeTracker = 1

    for proxyInstance, sketchConnections in jsonData.items():

        for routes in sketchConnections:
            sys.stdout.write(StanzaTemplate % {'location': "middle",
                                               'number': midTracker,
                                               'ip': routes['middle'],
                                               'engagementName': engagementName,
                                               'proxyName': proxyInstance})

            for edge in routes['edges']:
                sys.stdout.write(StanzaTemplate % {'location': "edge",
                                                   'number': endgeTracker,
                                                   'ip': edge,
                                                   'engagementName': engagementName,
                                                   'proxyName': f"middle-{midTracker}-sketch"})
                endgeTracker += 1

            midTracker += 1


def validateJson(jsonData):
    format_checker = FormatChecker()
    validate(instance=jsonData, schema=schema,
             format_checker=format_checker)


def diffJsons(jsonData, puppetJson):

    print("The differences in the new json data and the puppet json are as follows: \n")

    with open(jsonData, 'r') as new:
        with open(puppetJson, 'r') as puppet:
            diff = difflib.unified_diff(
                new.readlines(),
                puppet.readlines(),
                fromfile='new',
                tofile='puppet',
            )
            for line in diff:
                print(line, end='')

    print("Is this is what you want, please copy the new json file to the puppet module and commit it: \n\n")
    print(f"cp {jsonData} {puppetJson}")
    print(f"cd to the {puppetJson} directory")
    print(f"git commit -m 'new sketch config' sketch.json")
    print(f"git push homebase-<ENGAGEMENT>:/var/lib/git/infra -f  ")


if __name__ == "__main__":

    args = parse_args()

    if args.ssh and not args.name:
        sys.stderr.write("The --ssh argument requires --name\n")
        sys.exit(1)

    if args.puppet and not os.path.exists(args.puppet):
        sys.stderr.write(
            "--puppet requires the sketch.json deployed by puppet\n")
        sys.exit(1)

    jsonData = slurp_json(args.sketchJSON)

    outputbasename = os.path.splitext(args.sketchJSON)[0]

    if args.ssh:
        printStanza(jsonData, args.name)
        print()
        print(
            f"Use the above in your ~/.ssh/redteam-sshconfigs/configs/{args.name}")

    if args.graph:
        png_output_filename = outputbasename + ".png"
        dot = obj_to_dot(jsonData)
        run_dot(dot, png_output_filename)
        print(f"Wrote png graph as {png_output_filename}")

    if args.conflu:
        conflu_output_filename = outputbasename + ".conflu"
        with open(conflu_output_filename, "w") as f:
            f.write(obj_to_conflu(jsonData))
        print(f"Wrote confluence markup as {conflu_output_filename}")

    if args.puppet:
        puppetJson = slurp_json(args.puppet)
        diffJsons(args.sketchJSON, args.puppet)

    print()
    print("Have a nice day!")
    print("RED TEAM!")
