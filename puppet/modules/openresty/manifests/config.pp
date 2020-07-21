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

  exec {'restyreload':
      command => '/bin/systemctl restart openresty',
      path => ['/bin/', '/usr/bin'],
      refreshonly => true,
  }

}
