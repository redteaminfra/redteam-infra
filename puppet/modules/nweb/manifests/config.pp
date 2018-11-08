class nweb::config {

    exec { 'clone_nweb':
        command => "/usr/bin/git clone https://github.com/pierce403/nweb /opt/nweb",
        creates => '/opt/nweb',
    }

    file { '/opt/nweb':
        mode => '0755',
        ensure => present,
        require => Exec["clone_nweb"],
	}

    file { "/etc/systemd/system/nweb.service":
        path => '/etc/systemd/system/nweb.service',
        owner => 'root',
        group => 'root',
        mode => '600',
        ensure => present,
        source => "puppet:///modules/nweb/nweb.service",
        notify => Exec["reload-systemd"],
    }

    exec { "reload-systemd":
        command => "/bin/systemctl daemon-reload && /bin/systemctl enable nweb.service && /bin/systemctl start nweb.service",
    }

    file { "/etc/nginx/sites-available/nweb":
        path => '/etc/nginx/sites-available/nweb',
        ensure => present,
        source => "puppet:///modules/nweb/nweb.nginx",
    }

    file { "/etc/nginx/sites-enabled/nweb":
        path => '/etc/nginx/sites-enabled/nweb',
        ensure => 'link',
        target => '/etc/nginx/sites-available/nweb',
    }

    file { "/etc/nginx/sites-enabled/default":
        path => '/etc/nginx/sites-enabled/default',
        ensure => 'link',
        target => '/etc/nginx/sites-available/nweb',
        notify => Exec["nginx-start"],
    }

    exec { "nginx-start":
        command => "/bin/systemctl reload nginx.service && /bin/systemctl enable nginx.service && /bin/systemctl start nginx.service",
    }

    file { "/etc/systemd/system/nweb-agent.service":
        path => '/etc/systemd/system/nweb-agent.service',
        owner => 'root',
        group => 'root',
        mode => '600',
        ensure => present,
        source => "puppet:///modules/nweb/nweb-agent.service",
        notify => Exec["nweb-agent"],
    }

    exec { "nweb-agent":
        command => "/bin/systemctl daemon-reload && /bin/systemctl enable nweb-agent.service && /bin/systemctl start nweb-agent.service",
    }

    exec { "nmap-install":
        command => "/usr/bin/apt install -y nmap",
    }
    
    exec { "setup-server":
        cwd => "/opt/nweb/nweb-server",
        command => "/bin/bash setup-server.sh",
    }

    exec { "setup-agent":
        cwd => "/opt/nweb/nweb-agent",
        command => "/bin/bash setup-agent.sh",
    }

    exec { "install-nweb-dependencies":
        command => "/usr/bin/apt install -y wkhtmltopdf vncsnapshot",
    }

    exec { "download-elastic-dpkg":
        command => "/usr/bin/wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-6.2.1.deb -O /tmp/elastic.deb && /usr/bin/dpkg -i /tmp/elastic.deb",
        notify => Exec["enable-elastic"],
        creates => '/tmp/elastic.deb',
    } 

    exec { "enable-elastic":
        command => "/bin/systemctl enable elasticsearch.service && /bin/systemctl start elasticsearch.service"
    }
}
