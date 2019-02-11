node "default" {
    include 'hostsexternal'
    include 'gitpuppet'
    include 'ssh'
    include 'natlas'
    include 'unattendedupgrades'
    include 'yama'
    include 'mollyguard'

    package { ['default-jre']:
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
