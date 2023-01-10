# Copyright (c) 2023, Oracle and/or its affiliates.

class openresty::config {

    file { '/usr/local/openresty/nginx/conf/nginx.conf':
        path => '/usr/local/openresty/nginx/conf/nginx.conf',
        owner => 'root',
        mode => '644',
        ensure => present,
        source => "puppet:///modules/openresty/nginx.conf",
        require => Package['openresty'],
        notify => Exec['restyreload'],
    }

    file { '/var/log/openresty':
        ensure => 'directory',
        owner  => 'root',
        mode   => '0775',
        require => Package['openresty'],
        notify => Exec['restyreload'],
    }

    file { '/etc/logrotate.d/openresty':
        path => '/etc/logrotate.d/openresty',
        owner => 'root',
        mode => '644',
        ensure => present,
        source => "puppet:///modules/openresty/openresty",
        require => Package['openresty'],
    }

    exec {'restyreload':
        command => '/bin/systemctl restart openresty',
        path => ['/bin/', '/usr/bin'],
        refreshonly => true,
    }

}
