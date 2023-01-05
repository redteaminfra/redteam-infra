# Sketch Tooling

## What

This tooling allows an infrastructure maintainer to manage their sketch deployment. A json config will be used to track the middle and edge combinations for a specific proxy instance. This config will create opsec rules for instances firewalls through the `sketchopsec` puppet module.

In the upstream infra tree, the config in `sketchopsec` is `{}`. As you specialize the tree for your deployment, you should commit a new config to `sketchopsec`. You should validate this config with the tooling in the `sketchopsec` module prior to committing and deploying.

This tooling will also generate a png graph or a confluence markup table of the sketch routes for easier reporting.

## JSON

The JSON used for sketch is validated by the follow schema

```
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
```

This results in a configuration looking like the provided `example.json`

```
{
    "proxy01": [
        {
            "middle": "1.2.3.4",
            "edges": [
                "5.6.7.8",
                "9.8.7.6"
            ]
        },
        {
            "middle": "5.4.3.2",
            "edges": [
                "4.5.6.7",
                "7.6.5.4"
            ]
        }
    ],
    "proxy02": [
        {
            "middle": "2.3.4.5",
            "edges": [
                "11.12.13.14"
            ]
        }
    ]
}
```

You can add N+1 proxies to the configuration.

## sketch-json-config.py

**Note**: `sketch-json-config.py` requires the `Graphviz` package to be installed on the host OS in order to generate graphs 
with the `-g` option.

```
usage: sketchJSON [-h] -j SKETCHJSON [-s] [-n NAME] [-g] [-c] [-p PUPPET]

Sketch JSON Configuration.

optional arguments:
  -h, --help            show this help message and exit
  -j SKETCHJSON, --json SKETCHJSON
                        The json data for your sketch config
  -s, --ssh             Print SSH Stanza usage for sketch
  -n NAME, --name NAME  Name of the engagement
  -g, --graph           Make a png graph for confluence
  -c, --conflu          Make a markup table for confluence
  -p PUPPET, --puppet PUPPET
                        Path to the sketch.json used with puppet. This will be
                        in an
                        <infra>/puppet/modules/sketchopsec/files/sketch.json
```

### Generate SSH Stanza

```
./sketch-json-config.py --ssh --name example -j example.json

Host middle-1-sketch-example
    Hostname 1.2.3.4
    ProxyJump ssh proxy01-example
    IdentityFile ~/.ssh/sketchKey
    User root
```

### Validate a new json config

```
./sketch-json-config.py -p ~/Documents/OCI/redTeam/infra/redteam-infra-internal/puppet/modules/sketchopsec/files/sketch.json -j example.json
The differences in the new json data and the puppet json are as follows:

--- new
+++ puppet
@@ -1,26 +1,2 @@
 {
-    "proxy01": [
-       {
-           "middle": "1.2.3.4",
-           "edges": [
-               "5.6.7.8",
-               "9.8.7.6"
-           ]
-       },
-       {
-           "middle": "5.4.3.2",
-           "edges": [
-               "4.5.6.7",
-               "7.6.5.4"
-           ]
-       }
-    ],
-    "proxy02": [
-       {
-           "middle": "2.3.4.5",
-           "edges": [
-               "11.12.13.14"
-           ]
-       }
-    ]
 }
Is this is what you want, please copy the new json file to the puppet module and commit it:


cp example.json /home/ttimzen/Documents/OCI/redTeam/infra/redteam-infra-internal/puppet/modules/sketchopsec/files/sketch.json
cd to the /home/ttimzen/Documents/OCI/redTeam/infra/redteam-infra-internal/puppet/modules/sketchopsec/files/sketch.json directory
git commit -m 'new sketch config' sketch.json
git push homebase-<ENGAGEMENT>:/var/lib/git/infra -f

Have a nice day!
RED TEAM!
```

Copyright (c) 2022, Oracle and/or its affiliates.
