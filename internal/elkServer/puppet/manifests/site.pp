node "default" {
    include 'hostsinternal'
    include 'gitpuppet'
    include 'ssh'
    include 'unattendedupgrades'
    include 'mollyguard'

# ELK Setup

  class { 'elasticsearch':
    java_install => true,
    manage_repo  => true,
    repo_version => '5.x',
    restart_on_change => true,
  }

  elasticsearch::instance { 'es-01':
    config => {
      'network.host' => 'elk.infra.redteam',
    },
  }

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
      'elasticsearch.url' => 'http://elk.infra.redteam:9200',
    }
  }

  include 'logstashconfig'

}
