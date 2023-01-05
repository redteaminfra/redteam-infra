#!/usr/bin/env python3
# Copyright (c) 2022, Oracle and/or its affiliates.


import os

tags = ["infra"]

try:
    with open("/etc/infra/tags", "r") as f:
        for line in f.readlines():
            tags.append(line.strip())
except IOError:
    pass

try:
    for filename in os.listdir("/etc/infra/tags.d"):
        tags.append(filename)
except OSError:
    pass

line = ""
for tag in tags:
    line += (" -t " + tag)
print(line)
