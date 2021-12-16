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
    include 'irc'
    include 'basetools'
    # Ubuntu or Kali as base? Use homebasetoolsubuntu for ubuntu or homebasetoolskali for Kali
    include 'homebasetoolsubuntu'
    include 'etherpad'
    include 'yama'
    include 'mollyguard'
    include 'cleanup'
    include 'cloudagent'
    include 'sketchopsec'
    include 'logstashconfig'

    package { ['openjdk-8-jre-headless']:
    }

    class { 'golang':
      version => '1.13',
    }

    include 'docker'

    class { 'docker::compose':
    }

}
