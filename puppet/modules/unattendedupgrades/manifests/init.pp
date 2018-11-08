class unattendedupgrades {
  file { '/etc/apt/apt.conf.d/99unattended-upgrades':
    path => '/etc/apt/apt.conf.d/99unattended-upgrades',
    owner => 'root',
    mode => '644',
    ensure => 'present',
    source => 'puppet:///modules/unattendedupgrades/99unattended-upgrades'
  }
}
