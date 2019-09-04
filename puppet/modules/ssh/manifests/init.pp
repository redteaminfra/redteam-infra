class ssh {

    file { '/etc/infra/git-sshkeys.sh':
        path => "/etc/infra/git-sshkeys.sh",
        owner => 'root',
        mode => '775',
        require => File['/etc/infra'],
        ensure => present,
        source => "puppet:///modules/ssh/git-sshkeys.sh"
    }

    file { '/etc/infra/ssh_tags.py':
        path => "/etc/infra/ssh_tags.py",
        owner => 'root',
        mode => '755',
        require => File['/etc/infra'],
        ensure => present,
        source => "puppet:///modules/ssh/ssh_tags.py"
    }

    file { '/etc/infra/tags.d':
        owner => 'root',
        mode => '755',
        require => File['/etc/infra'],
        ensure => directory
    }

    file { '/etc/infra/tags.d/syncrobot':
       path => "/etc/infra/tags.d/syncrobot",
       owner => 'root',
       mode => '644',
       ensure => present,
       require => File['/etc/infra/tags.d'],
       content => ""
    }

    file { '/etc/infra/tags.d/core':
       path => "/etc/infra/tags.d/core",
       owner => 'root',
       mode => '644',
       ensure => present,
       require => File['/etc/infra/tags.d'],
       content => ""
    }

    cron { gitsshkeys:
        command => "/etc/infra/git-sshkeys.sh 2>&1 | /usr/bin/logger -t git-sshkeys",
        environment => "PATH=/bin:/usr/bin:/sbin:/usr/sbin",
        user    => root,
        minute  => '*/10'
    }

    file_line { 'git-shell':
      ensure => present,
      path => '/etc/shells',
      line => '/usr/bin/git-shell'
    }

}
