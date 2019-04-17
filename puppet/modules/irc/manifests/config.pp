class irc::config {

    exec { 'clone_irc':
        command => "/usr/bin/git clone https://github.com/jrosdahl/miniircd /opt/irc",
		creates => '/opt/irc',
		notify => Exec["localhost_bind"],
    }

    file { '/opt/irc':
        mode => '0755',
        ensure => directory,
        recurse => true,
        require => Exec["clone_irc"],
	    owner => 'irc',
    }

	exec { 'localhost_bind':
		command => "/bin/sed -i 's/s.bind((self.address, port))/s.bind((\"127.0.0.1\", port))/g' /opt/irc/miniircd",
	}

    file { "/opt/irc/irc-wrapper.sh":
        path => '/opt/irc/irc-wrapper.sh',
        ensure => present,
        source => "puppet:///modules/irc/irc-wrapper.sh",
    }

    file { "/etc/systemd/system/irc.service":
        path => '/etc/systemd/system/irc.service',
        owner => 'root',
        group => 'root',
        mode => '600',
        ensure => present,
        source => "puppet:///modules/irc/irc.service",
        notify => Exec["reload-systemd-irc"],
    }

    exec { "reload-systemd-irc":
        command => "/bin/systemctl daemon-reload && /bin/systemctl enable irc.service && /bin/systemctl start irc.service",
    }

}
