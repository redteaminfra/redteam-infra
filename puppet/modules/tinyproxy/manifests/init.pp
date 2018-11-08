class tinyproxy {
  package { ['tinyproxy']:
    ensure => 'installed',
    notify => File['/etc/tinyproxy.conf'],
  }

  file { '/etc/tinyproxy.conf':
      path => '/etc/tinyproxy.conf',
      mode => '644',
      ensure => present,
      source => 'puppet:///modules/tinyproxy/tinyproxy.conf',
      require => Package['tinyproxy'],
      notify => Exec['tinyproxyreload'],
  }

  # we do this because we change the config after the package is
  # installed, which starts the service
  exec {'tinyproxyreload':
      command => '/bin/systemctl reload tinyproxy.service',
      path => ['/bin/', '/usr/bin'],
      refreshonly => true,
  }
}
