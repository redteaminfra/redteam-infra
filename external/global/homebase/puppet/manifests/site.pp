# Copyright (c) 2022, Oracle and/or its affiliates.

# DO NOT INCLUDE UNATTENDED UPGRADES
# You do not want homebase to reboot during an operation due to upgrades
node "default" {
    include 'hostsexternal'
    include 'gitserver'
    include 'gitpuppet'
    include 'opsec'
    include 'loot'
    include 'ssh'
    include 'volunteerssh'
    include 'basetools'
    # Ubuntu or Kali as base? Use homebasetoolsubuntu for ubuntu or homebasetoolskali for Kali
    include 'homebasetoolsubuntu'
    include 'yama'
    include 'mollyguard'
    include 'cleanup'
    include 'cloudagent'
    include 'sketchopsec'
    include 'logstashconfig'
    include 'nfsserver'

    package { ['openjdk-8-jre-headless']:
    }

    class { 'golang':
      version => '1.17',
    }

    include 'docker'

    class { 'docker::compose':
    }

}
