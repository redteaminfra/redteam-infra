class volunteerssh {
    file { '/etc/infra/tags.d/volunteer':
        path => "/etc/infra/tags.d/volunteer",
        owner => 'root',
        mode => '644',
        ensure => present,
        require => File['/etc/infra/tags.d'],
        content => ""
    }
}
