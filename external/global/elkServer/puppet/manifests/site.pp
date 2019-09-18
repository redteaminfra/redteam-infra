node "default" {
    include 'hostsexternal'
    include 'gitpuppet'
    include 'ssh'
    include 'unattendedupgrades'
    include 'yama'
    include 'mollyguard'
  #  include 'monitoring'
    include 'cleanup'

# ELK Setup
#  package { ['openjdk-8-jre-headless']:
#    ensure => 'installed',
#    notify => Class['elasticsearch']
#  }

#  class { 'elasticsearch':
#    restart_on_change => true,
#    repo_version => '5.x',
#    manage_repo => true,
#    require => Package['openjdk-8-jre-headless']
#  }

#   elasticsearch::instance { 'es-01':
#    config => {
#      'network.host' => 'elk.infra.redteam',
#    }
#  }

  class { 'logstash':
    logstash_group  => 'adm',
    settings => {
      'http.host' => 'elk.infra.redteam',
    }
  }

  logstash::configfile { 'inputs':
    source => "puppet:///modules/elk/ls.conf",
  }

  class { 'kibana' :
    config => {
      'server.host'       => 'elk.infra.redteam',
      'server.port'       => '5601',
      'elasticsearch.url' => 'http://localhost:9200',
    }
  }

  include 'logstashconfig'
  include 'elkconfig'
}
