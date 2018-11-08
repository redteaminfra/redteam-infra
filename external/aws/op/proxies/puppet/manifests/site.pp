node "default" {
  include 'hostsexternal'
  include 'gitpuppet'
  include 'ssh'
  include 'dante'
  include 'volunteerssh'
  include 'modrewrite'
  include 'unattendedupgrades'
  include 'yama'
  include 'nmap'
  include 'mollyguard'
  include 'proxytools'
  include 'backflips'
  include 'tinyproxy'

  package { ['default-jre']:
      ensure => 'installed',
      notify => Class['logstash']
  }

  class { 'logstash':
      logstash_group => 'adm'
  }

  logstash::configfile { 'inputs':
    source => "puppet:///modules/elk/proxy.conf",
  }

  include 'logstashconfig'

}
