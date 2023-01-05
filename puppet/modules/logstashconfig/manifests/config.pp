# Copyright (c) 2022, Oracle and/or its affiliates.

class logstashconfig::config {


# /etc/default/logstash
# This ensures that `hostname` and `server` are configured for our logstash filter

  exec { "add_hostname_for_logstash":
    command => "/bin/bash -c 'echo hostname=$(hostname)' >> /etc/default/logstash",
    onlyif => "/usr/bin/test -f /etc/default/logstash",
    unless => "/bin/grep -q hostname /etc/default/logstash",
    notify => Exec["named_logstash"],
  }

  exec { "named_logstash" :
    command => "/bin/bash -c 'echo server=elk-$(hostname | cut -d - -f2- | tr -d \"\n\").infra.redteam' >> /etc/default/logstash",
    unless => "/bin/grep -q server /etc/default/logstash",
    refreshonly => true,
  }

# etc/logstash/conf.d/inputs

  if $hostname =~ /^homebase/ {
    $input = "homebase.conf"
  }
  elsif $hostname =~ /^proxy/ {
    $input = "proxy.conf"
  }
  elsif $hostname =~ /^elk/ {
    $input = "elk.conf"
  }
  else {
    $input = "somethingiswrong.conf"
 }

  file {'/etc/logstash/conf.d/inputs':
    path => '/etc/logstash/conf.d/inputs',
    owner => 'root',
    mode => '644',
    ensure => present,
    source => "puppet:///modules/logstashconfig/$input",
    require => Package['logstash'],
    notify => Exec['logstashrestart'],
    }

# /etc/logstash/logstash.yml

  file { '/etc/logstash/logstash.yml':
      path => '/etc/logstash/logstash.yml',
      owner => 'root',
      mode => '644',
      ensure => present,
      source => "puppet:///modules/logstashconfig/logstash.yml",
      require => Package['logstash'],
      notify => Exec['logstashrestart'],
  }

# /etc/systemd/system/logstash.service

  file { '/etc/systemd/system/logstash.service':
      path => '/etc/systemd/system/logstash.service',
      owner => 'root',
      mode => '644',
      ensure => present,
      source => "puppet:///modules/logstashconfig/logstash.service",
      require => Package['logstash'],
      notify => Exec['logstashreload'],
  }

  exec {'logstashreload':
      command => '/bin/systemctl daemon-reload',
      refreshonly => true,
      notify => Exec['logstashrestart'],
  }

  exec {'logstashrestart':
      command => '/bin/systemctl restart logstash',
      refreshonly => true,
  }

}
