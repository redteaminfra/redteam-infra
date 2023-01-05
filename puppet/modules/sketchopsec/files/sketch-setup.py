#!/usr/bin/env python3
# Copyright (c) 2022, Oracle and/or its affiliates.


import iptc
import json
import os

chainRules = None
middles = []
edges = []

# Get the first part of an instances hostname, e.g; proxy01-engagement becomes proxy01
hostname = os.uname()[1].split('-')[0]


def slurp_json(filename):
    contents = None
    with open(filename) as f:
        contents = f.read()
    obj = json.loads(contents)

    # Validate the incoming json object against our schema
    return obj


def getOUTPUT():
    table = iptc.Table(iptc.Table.FILTER)
    chain = iptc.Chain(table, "OUTPUT")
    return chain


def getInstances(jsonData):

    for proxy, sketchConnections in jsonData.items():

        for routes in sketchConnections:
            # Only block the middles for this host if the proxy is not meant to reach out to them
            if proxy != hostname:
                middles.append(routes['middle'])

            for edge in routes['edges']:
                edges.append(edge)


def addRule(AddIPS, outputChain):

    for IP in AddIPS:
        rule = iptc.Rule()
        rule.dst = IP
        target = iptc.Target(rule, "DROP")
        rule.target = target
        print(rule.target)
        outputChain.insert_rule(rule)


def generateDelta(outputChain):

    existingRules = []
    for rule in outputChain.rules:
        # Get just the IPs
        existingRules.append(rule.dst.split('/')[0])

    toAdd = []

    # Add middles
    [toAdd.append(x)
     for x in middles if x not in existingRules]

    # Add Edges
    [toAdd.append(x)
     for x in edges if x not in existingRules]

    return toAdd


sketchJson = slurp_json("/opt/sketch/sketch.json")

getInstances(sketchJson)

outputChain = getOUTPUT()

newIPs = generateDelta(outputChain)

addRule(newIPs, outputChain)
