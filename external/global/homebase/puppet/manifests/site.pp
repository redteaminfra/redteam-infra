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
    # Ubuntu or Kali as base? Use homebasetoolsubuntu for ubuntu or homebasetoolskali for Kali
    include 'homebasetoolsubuntu'
    include 'etherpad'
    include 'yama'
    include 'mollyguard'
    include 'cleanup'

    package { ['openjdk-8-jre-headless']:
        ensure => 'installed',
        notify => Class['logstash']
    }

    class { 'logstash':
     logstash_group => "adm",
    }

    logstash::configfile { 'inputs':
      source => "puppet:///modules/elk/ls.conf",
    }

    include 'logstashconfig'
    class { 'golang':
      version => '1.13',
    }
}
