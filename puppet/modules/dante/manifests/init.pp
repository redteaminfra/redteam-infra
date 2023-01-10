# Copyright (c) 2023, Oracle and/or its affiliates.

class dante {
    package { ['dante-server']:
        ensure => 'installed',
        notify => File['/etc/danted.conf']
    }

    file { '/etc/danted.conf':
        path => '/etc/danted.conf',
        owner => 'root',
        mode => '644',
        ensure => present,
        content => template('dante/danted.conf.erb'),
        require => Package['dante-server']
    }

    # we do this because we change the config after the package is
    # installed, which starts the service
    exec {'stop':
        command => 'bash -c "/etc/init.d/danted stop || true"',
        path => ['/bin/', '/usr/bin'],
        refreshonly => true,
        notify => Exec['start']
    }

    # we start the service unconditionally, which will do nothing if
    # the service is already started.
    exec {'start':
        command => 'bash -c "/etc/init.d/danted start || true"',
        path => ['/bin/', '/usr/bin']
    }
}
