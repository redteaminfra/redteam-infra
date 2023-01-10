# Copyright (c) 2023, Oracle and/or its affiliates.

node "default" {
    include 'hostsexternal'
    include 'gitpuppet'
    include 'ssh'
    include 'unattendedupgrades'
    include 'yama'
    include 'mollyguard'
    include 'basetools'
  # include 'monitoring'
    include 'cleanup'
    include 'cloudagent'
    include 'sketchopsec'
    include 'logstashconfig'

    include 'docker'

    class { 'docker::compose':
    }

    include 'elastickibana'

}
