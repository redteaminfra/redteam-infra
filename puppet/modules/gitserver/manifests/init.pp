class gitserver {

    $gitdir = '/var/lib/git'
    $gitinfrarepo = "${gitdir}/infra"
    $gitsshrepo = "${gitdir}/sshKeys"

    package { ['git-daemon-sysvinit']:
        ensure => 'installed',
        notify => [Exec['gitsshbare'], Exec['gitinfrabare']]
    }

    file { '/etc/default/git-daemon':
        path => '/etc/default/git-daemon',
        owner => 'root',
        mode => '644',
        ensure => present,
        source => "puppet:///modules/gitserver/git-daemon",
        require => Package['git-daemon-sysvinit'],
        notify => Exec['enable-git-daemon']
    }

    exec {'enable-git-daemon':
        command => 'systemctl enable git-daemon.service',
        path => ['/bin/', '/usr/bin'],
        refreshonly => true,
        notify => Exec['start-git-daemon']
    }

    exec {'start-git-daemon':
        command => 'systemctl start git-daemon.service',
        path => ['/bin/'],
        refreshonly => true,
        require => Exec['enable-git-daemon']
    }

    group { 'infra':
        name => 'infra',
        ensure => 'present'
    }

    exec { 'gitinfrabare':
        command => "git init --bare --shared=group ${gitinfrarepo}",
        user => 'root',
        group => 'infra',
        cwd => "${gitdir}",
        path => ['/usr/bin/'],
        creates => ["${gitinfrarepo}"],
        require => [ Package['git-daemon-sysvinit'], Group['infra'] ],
        notify => [ Exec['unpack'], File_Line["${gitinfrarepo}/config"] ]
    }

    file_line { "${gitinfrarepo}/config":
        path => "${gitinfrarepo}/config",
        line => "\tdenyNonFastforwards = false",
        match => "denyNonFastforwards = true",
        require => [ Exec['gitinfrabare'] ]
    }

    exec { 'gitsshbare':
        command => "git init --bare --shared=group ${gitsshrepo}",
        user => 'root',
        group => 'infra',
        cwd => "${gitdir}",
        path => ['/usr/bin/'],
        creates => "${gitsshrepo}",
        notify => [ File_Line["${gitsshrepo}/config"] ],
        require => [ Package['git-daemon-sysvinit'], Group['infra'] ]
    }

    file_line { "${gitsshrepo}/config":
        path => "${gitsshrepo}/config",
        line => "\tdenyNonFastforwards = false",
        match => "denyNonFastforwards = true",
        require => [ Exec['gitinfrabare'] ]
    }

    exec { 'unpack':
        command => "bash -c \"cd $(mktemp -d); tar xavf /tmp/host-share/bootstrap-puppet.tgz; git push ${gitinfrarepo} master\"",
        user => 'root',
        group => 'infra',
        path => ['/bin', '/usr/bin/'],
        refreshonly => true
    }

}
