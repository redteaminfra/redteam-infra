# Copyright (c) 2022, Oracle and/or its affiliates.

node "default" {
  include 'hostsexternal'
  include 'gitpuppet'
  include 'ssh'
  include 'dante'
  include 'volunteerssh'
  include 'unattendedupgrades'
  include 'yama'
  include 'nmap'
  include 'mollyguard'
  include 'basetools'
  include 'proxytools'
  #include 'tinyproxy'
  include 'sshproxy'
  include 'cleanup'
  include 'cloudagent'
  include 'openresty'
  include 'sketchopsec'
  include 'logstashconfig'
  include 'nfsclient'


  package { ['openjdk-8-jre-headless']:
  }
}
