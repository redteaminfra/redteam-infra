class gitpuppet {

    $gitdir = '/var/lib/git'
    $gitrepo = "${gitdir}/infra"


    file { '/etc/infra':
        ensure => 'directory',
    }

    exec { 'site.pp':
        command => 'bash -c "cp -v $(readlink /tmp/host-share/puppet/manifests/site.pp) /etc/infra"',
        creates => '/etc/infra/site.pp',
        require => File['/etc/infra'],
        path => ['/bin/', '/usr/bin/']
    }

    file { '/etc/infra/git-puppet-apply.sh':
        path => "/etc/infra/git-puppet-apply.sh",
        owner => 'root',
        mode => '775',
        require => File['/etc/infra'],
        ensure => present,
        source => "puppet:///modules/gitpuppet/git-puppet-apply.sh"
    }

    cron { git-puppet-apply:
        command => "/etc/infra/git-puppet-apply.sh 2>&1 | /usr/bin/logger -t git-puppet-apply",
        user    => root,
        minute  => '*/5'
    }
}
