class modrewrite::config {

    file { "/root/override.patch":
        path => '/root/override.patch',
        owner => 'root',
        group => 'root',
        mode => '660',
        ensure => present,
        source => "puppet:///modules/modrewrite/override.patch",
        notify => Exec['override'],
	}

	exec { "override":
        command => "/bin/bash -c 'patch -l -N --dry-run /etc/apache2/apache2.conf /root/override.patch > /dev/null; if [ $? -eq 0 ]; then patch -l -N /etc/apache2/apache2.conf /root/override.patch; fi'",
        notify => Exec['enable_a2enmod'],
	}

    exec { "enable_a2enmod":
        command => "/usr/sbin/a2enmod rewrite proxy proxy_http",
        notify => Exec['systemctl-apache2'],
    }

    exec { "systemctl-apache2":
	  command => "/bin/systemctl enable apache2 && /bin/systemctl restart apache2",
	}

    file { "/var/www/html/.htaccess":
        path => '/var/www/html/.htaccess',
        owner => 'root',
        group => 'root',
        mode => '644',
        ensure => present,
        replace => 'no',
        source => "puppet:///modules/modrewrite/.htaccess",
	}
}
