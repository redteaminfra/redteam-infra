# Copyright (c) 2023, Oracle and/or its affiliates.

class nfsserver::config {
    file { '/dropbox':
    ensure => 'directory',
    owner => 'nobody',
    group => 'redteam',
    mode => '770',
    notify => File['/etc/exports'],
  }

  file { '/etc/exports':
      path => '/etc/exports',
      mode => '644',
      ensure => present,
      source => 'puppet:///modules/nfsserver/exports',
      require => Package['nfs-kernel-server'],
      notify => Exec['nfsrestart'],
  }

  exec {'nfsrestart':
      command => '/bin/systemctl restart nfs-kernel-server.service',
      refreshonly => true,
  }
}
