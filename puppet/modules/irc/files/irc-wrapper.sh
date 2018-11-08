#!/bin/bash

cd /opt/irc
python miniircd --verbose --debug --channel-log-dir irclogs --setuid irc
