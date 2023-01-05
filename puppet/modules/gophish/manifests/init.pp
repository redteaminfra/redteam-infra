# Copyright (c) 2022, Oracle and/or its affiliates.

class gophish {

    file { '/opt/gophish':
        ensure => 'directory',
    }

    file { '/opt/gophish/logs':
        ensure => 'directory',
        owner => '1000',
        mode => '644',
        require => File['/opt/gophish']
    }

    file { '/opt/gophish/database':
        ensure => 'directory',
        owner => '1000',
        mode => '644',
        require => File['/opt/gophish']
    }

    file { '/opt/gophish/keys':
        ensure => 'directory',
        owner => '1000',
        mode => '644',
        require => File['/opt/gophish']
    }

    file { '/opt/gophish/static':
        ensure => 'directory',
        owner => '1000',
        mode => '644',
        require => File['/opt/gophish']
    }

    file { '/opt/gophish/static/endpoint':
        ensure => 'directory',
        owner => '1000',
        mode => '644',
        require => File['/opt/gophish/static']
    }

    file { '/opt/gophish/docker-compose.yml':
        ensure => present,
        owner => 'root',
        mode => '644',
        source => 'puppet:///modules/gophish/docker-compose.yml',
        require => File['/opt/gophish']
    }

    file { '/opt/gophish/config.json':
        ensure => present,
        owner => 'root',
        mode => '644',
        source => 'puppet:///modules/gophish/config.json'
    }

    docker_compose { 'gophish':
        compose_files => ['/opt/gophish/docker-compose.yml'],
        ensure => present,
        require => File['/opt/gophish/docker-compose.yml',
                        '/opt/gophish/config.json',
                        '/opt/gophish/static/endpoint',
                        '/opt/gophish/database',
                        '/opt/gophish/logs',
                        '/opt/gophish/keys'],
    }
}
