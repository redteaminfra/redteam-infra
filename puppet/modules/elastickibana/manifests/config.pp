class elastickibana::config {

# set mx_map_count

  exec { "set_max_map_count":
      command => "/sbin/sysctl -w vm.max_map_count=262144",
      unless => "/bin/grep -q max_map_count /etc/sysctl.conf",
  }

# make mx_map_count persistent

  exec { "persist_max_map_count":
      command => "/bin/bash -c 'echo \"vm.max_map_count=262144\" | /usr/bin/tee /etc/sysctl.conf'",
      unless => "/bin/grep -q max_map_count /etc/sysctl.conf",
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
