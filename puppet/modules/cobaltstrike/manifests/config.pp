class cobaltstrike::config {

    file { "/opt/cobaltstrike.tgz":
        path => '/opt/cobaltstrike.tgz',
        owner => 'root',
        group => 'root',
        mode => '660',
        ensure => present,
        source => "puppet:///modules/cobaltstrike/cobaltstrike.tgz",
        notify => Exec["make_cobalt"],
    }

    exec { "cp_license":
        command => '/bin/cp -v /tmp/host-share/.cobaltstrike.license /root',
        onlyif  => '/usr/bin/test ! -e /root/.cobaltstrike.license',
    }

    exec { "make_cobalt":
        command => "/bin/tar -zxvf /opt/cobaltstrike.tgz -C /opt/ && chown -R root:root /opt/cobaltstrike",
        require => File["/opt/cobaltstrike.tgz"],
        creates => '/opt/cobaltstrike',
    }

    file { "/opt/cobaltstrike/update.sh":
        path => '/opt/cobaltstrike/update.sh',
        owner => 'root',
        group => 'root',
        mode => '770',
        ensure => present,
        source => "puppet:///modules/cobaltstrike/update.sh",
        notify => Exec["update_cobalt"],
    }

    exec { "update_cobalt":
        command => "/bin/bash /opt/cobaltstrike/update.sh",
        user => "root",
        refreshonly => true, # update cobalt the first time
    }

    file { "/opt/c2-monitor.cna":
        path => '/opt/c2-monitor.cna',
        owner => 'root',
        group => 'root',
        mode => '770',
        ensure => present,
        source => "puppet:///modules/cobaltstrike/c2-monitor.cna",
    }

    file { "/opt/IRCBot.cna":
        path => '/opt/IRCBot.cna',
        owner => 'root',
        group => 'root',
        mode => '770',
        ensure => present,
        source => "puppet:///modules/cobaltstrike/IRCBot.cna",
    }

    file { "/opt/cobaltstrike/init.sh":
        path => '/opt/cobaltstrike/init.sh',
        owner => 'root',
        group => 'root',
        mode => '770',
        ensure => present,
        source => "puppet:///modules/cobaltstrike/init.sh",
        notify => Exec["make_init"],
    }

   exec {"make_init":
        cwd => '/opt/cobaltstrike',
        command => '/bin/bash init.sh',
        refreshonly => "true",
   }

    file { "/opt/cobaltstrike/agscript":
        path => '/opt/cobaltstrike/agscript',
        owner => 'root',
        group => 'root',
        mode => '755',
        ensure => present,
        source => "puppet:///modules/cobaltstrike/agscript",
    }

    file { "/opt/malleable":
        path => '/opt/malleable',
        owner => 'root',
        group => 'root',
        mode => '770',
        ensure => 'directory',
        notify => File["/opt/malleable/amazon.profile"]
    }

    file { "/opt/malleable/amazon.profile":
        owner => 'root',
        group => 'root',
        mode => '770',
        ensure => present,
        require => File["/opt/malleable"],
        source => "puppet:///modules/cobaltstrike/amazon.profile",
    }

    file { "/etc/systemd/system/cobaltstrike.service":
        path => '/etc/systemd/system/cobaltstrike.service',
        owner => 'root',
        group => 'root',
        mode => '600',
        ensure => present,
        source => "puppet:///modules/cobaltstrike/cobaltstrike.service",
        notify => Exec["reload-systemd-cobalt"],
    }

    file { "/usr/share/pixmaps/cobalt-strike.png":
        path => "/usr/share/pixmaps/cobalt-strike.png",
        owner => 'root',
        group => 'root',
        mode => '644',
        ensure => present,
        source => "puppet:///modules/cobaltstrike/cobalt-strike.png",
    }

    exec { "reload-systemd-cobalt":
        command => "/bin/systemctl daemon-reload && /bin/systemctl enable cobaltstrike.service && /bin/systemctl start cobaltstrike.service",
        require => File["/etc/systemd/system/cobaltstrike.service"],
    }

    exec { "extract_artifact":
        cwd => '/opt',
        command => '/bin/tar -zxf /tmp/host-share/artifact.tgz',
        onlyif  => '/usr/bin/test ! -d /opt/artifact && /usr/bin/test -e /tmp/host-share/artifact.tgz',
        notify => Exec["make_artifact"],
    }

   exec {"make_artifact":
        cwd => '/opt/artifact',
        command => '/bin/bash build.sh',
        refreshonly => "true",
        notify => Exec["artifact_permissions"],
   }

   exec {"artifact_permissions":
        cwd => '/opt/artifact',
        command => '/bin/chown -R :redteam /opt/artifact',
        refreshonly => "true",
   }

    file { "/etc/systemd/system/ircbot.service":
        path => '/etc/systemd/system/ircbot.service',
        owner => 'root',
        group => 'root',
        mode => '600',
        ensure => present,
        source => "puppet:///modules/cobaltstrike/ircbot.service",
        notify => Exec["reload-systemd-ircbot"],
    }

    exec { "reload-systemd-ircbot":
        command => "/bin/systemctl daemon-reload && /bin/systemctl enable ircbot.service && /bin/systemctl start ircbot.service",
        require => File["/etc/systemd/system/ircbot.service"],
    }

    file { "/etc/systemd/system/c2monitor.service":
        path => '/etc/systemd/system/c2monitor.service',
        owner => 'root',
        group => 'root',
        mode => '600',
        ensure => present,
        source => "puppet:///modules/cobaltstrike/c2monitor.service",
        notify => Exec["reload-systemd-c2monitor"],
    }

    exec { "reload-systemd-c2monitor":
        command => "/bin/systemctl daemon-reload && /bin/systemctl enable c2monitor.service && /bin/systemctl start c2monitor.service",
        require => File["/etc/systemd/system/c2monitor.service"],
    }
}
