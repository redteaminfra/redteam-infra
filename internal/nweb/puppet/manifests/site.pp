node "default" {
  include 'gitpuppet'
  include 'natlas'
  include 'ssh'
  include 'unattendedupgrades'
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
