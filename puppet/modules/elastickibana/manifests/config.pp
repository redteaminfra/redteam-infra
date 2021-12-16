class elastickibana::config {

# set mx_map_count

  file { "/etc/sysctl.d/98-max-map-count.conf":
    path => "/etc/sysctl.d/98-max-map-count.conf",
    owner => 'root',
    group => 'root',
    mode => '644',
    ensure => present,
    source => "puppet:///modules/elastickibana/98-max-map-count.conf",
    notify => Exec["elastic-sysctl"],
  }

  exec { "elastic-sysctl":
    command => "/sbin/sysctl -q --system"
  }

# docker compose management

   file { '/opt/elastickibana':
     ensure => 'directory',
   }

  file { '/opt/elastickibana/docker-compose.yml':
      ensure => present,
      owner => 'root',
      mode => '644',
      source => 'puppet:///modules/elastickibana/docker-compose.yml',
      require => File['/opt/elastickibana']
  }

  docker_compose { 'elastickibana':
    compose_files => ['/opt/elastickibana/docker-compose.yml'],
    ensure => present,
    require => File['/opt/elastickibana/docker-compose.yml'],
  }
}
