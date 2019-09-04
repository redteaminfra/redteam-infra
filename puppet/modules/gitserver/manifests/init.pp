class gitserver {

    $gitdir = '/var/lib/git'
    $gitinfrarepo = "${gitdir}/infra"
    $gitsshrepo = "${gitdir}/sshkeys"

    package { ['git']:
        ensure => 'installed',
        notify => [Exec['gitsshbare'], Exec['gitinfrabare']]
    }

    # gitdaemon:x:189:65534::/nonexistent:/usr/sbin/nologin
    user { 'gitdaemon':
      ensure => 'present',
      gid => '65534',
      home => '/nonexistent',
      password => '*',
      password_max_age => '99999',
      password_min_age => '0',
      shell => '/usr/sbin/nologin',
      uid => '189'
    }

    file { '/etc/systemd/system/git-daemon.service':
        path => '/etc/systemd/system/git-daemon.service',
        owner => 'root',
        mode => '644',
        ensure => present,
        source => "puppet:///modules/gitserver/git-daemon.service",
        require => Package['git'],
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
        require => [User['gitdaemon'], Exec['enable-git-daemon']]
    }

    group { 'infra':
        name => 'infra',
        ensure => 'present'
    }

    file {'/var/lib/git':
        ensure => directory,
        recurse => true,
        owner => "gitdaemon",
        require => User['gitdaemon'],
    }

    exec { 'gitinfrabare':
        command => "git init --bare --shared=group ${gitinfrarepo}",
        user => 'root',
        group => 'infra',
        cwd => "${gitdir}",
        path => ['/usr/bin/'],
        creates => ["${gitinfrarepo}"],
        require => [ Package['git'], Group['infra'] ],
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
        require => [ Package['git'], Group['infra'] ]
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
