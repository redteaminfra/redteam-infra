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
  include 'proxytools'
  #include 'tinyproxy'
  include 'sshproxy'
  include 'cleanup'
  include 'waybackdownloader'
  include 'cloudagent'
  include 'openresty'
  include 'sketchopsec'

  package { ['openjdk-8-jre-headless']:
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
