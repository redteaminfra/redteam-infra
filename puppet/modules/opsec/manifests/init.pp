class opsec {

    file { '/etc/network/if-pre-up.d/99-opsec':
        path => '/etc/network/if-pre-up.d/99-opsec',
        mode => '755',
        owner => 'root',
        ensure => present,
        source => 'puppet:///modules/opsec/99-opsec',
    }
}
