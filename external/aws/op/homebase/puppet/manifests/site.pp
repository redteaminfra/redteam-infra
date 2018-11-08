node "default" {
    include 'cobaltstrike'
    include 'hostsexternal'
    include 'gitserver'
    include 'gitpuppet'
    include 'opsec'
    include 'loot'
    include 'ssh'
    include 'volunteerssh'
    include 'irc'
    include 'homebasetools'
    include 'etherpad'
    include 'yama'
    include 'mollyguard'

   class { 'logstash':
     logstash_group => "adm"
   }

    logstash::configfile { 'inputs':
      source => "puppet:///modules/elk/ls.conf",
    }

    include 'logstashconfig'

}
