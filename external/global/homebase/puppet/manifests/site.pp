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

    package { ['openjdk-8-jre-headless']:
        ensure => 'installed',
        notify => Class['logstash']
    }

    class { 'logstash':
     logstash_group => "adm",
      settings => {
        'http.host' => 'elk.infra.redteam',
      }
    }

    logstash::configfile { 'inputs':
      source => "puppet:///modules/elk/ls.conf",
    }

    include 'logstashconfig'
#    include 'cobaltstrike'

}
