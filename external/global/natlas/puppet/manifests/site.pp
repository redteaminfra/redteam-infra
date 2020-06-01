node "default" {
    include 'hostsexternal'
    include 'gitpuppet'
    include 'ssh'
    include 'natlasserver'
    include 'natlasagent'
    include 'unattendedupgrades'
    include 'yama'
    include 'mollyguard'
    include 'cleanup'
    include 'cloudagent'

    package { ['openjdk-8-jre-headless']:
        ensure => 'installed',
        notify => Class['logstash']
    }

    class { 'logstash':
        logstash_group => 'adm'
    }

    logstash::configfile { 'inputs':
      source => "puppet:///modules/elk/ls.conf",
    }

    include 'logstashconfig'

}
