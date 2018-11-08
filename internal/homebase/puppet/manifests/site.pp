node "default" {
    
  include 'hostsinternalhb'
  include 'gitserver'
  include 'gitpuppet'
  include 'loot'
  include 'ssh'
  include 'volunteerssh'
  include 'irc'
  include 'homebasetoolsubuntu'
  include 'cobaltstrike'
  include 'unattendedupgrades'
  include 'etherpad'
  include 'mollyguard'

  class { 'logstash':
    logstash_group => "adm"
  }

  logstash::configfile { 'inputs':
    source => "puppet:///modules/elk/ls.conf",
  }

  include 'logstashconfig'

}
