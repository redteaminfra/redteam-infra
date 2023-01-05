# Copyright (c) 2022, Oracle and/or its affiliates.

class natlasserver::config {

    exec { 'download-natlas-server':
        command => "/bin/mkdir -p /opt/natlas && /usr/bin/curl https://github.com/natlas/natlas/releases/download/v0.5.4/natlas-server-0.5.4.tgz -L -o /opt/natlas/natlas-server.tgz",
        creates => '/opt/natlas/natlas-server.tgz',
        notify => Exec["untar-natlas-server"],
    }

    exec { 'untar-natlas-server':
        command => "/bin/tar -zxf natlas-server.tgz",
        cwd => "/opt/natlas",
        creates => '/opt/natlas/natlas-server',
        require => Exec["download-natlas-server"],
    }

    exec { "setup-elastic":
        cwd => "/opt/natlas/natlas-server",
        command => "/bin/bash setup-elastic.sh",
        require => Exec["untar-natlas-server"],
    }

    exec {"sed-server":
        command => "/bin/sed 's/127.0.0.1/0.0.0.0/g' /opt/natlas/natlas-server/run-server.sh  -i",
        require => Exec["untar-natlas-server"],
    }

    exec {"setup-secret":
        cwd => "/opt/natlas/natlas-server",
        command => "/bin/echo SECRET_KEY=$(openssl rand -base64 32) >> .env",
        require => Exec["untar-natlas-server"],
    }

    exec { "setup-server":
        cwd => "/opt/natlas/natlas-server",
        command => "/bin/bash setup-server.sh",
        require => Exec["setup-secret"],
    }


    file { "/etc/systemd/system/natlas.service":
        path => '/etc/systemd/system/natlas.service',
        owner => 'root',
        group => 'root',
        mode => '600',
        ensure => present,
        source => "puppet:///modules/natlasserver/natlas.service",
        notify => Exec["reload-systemd"],
    }

    exec { "reload-systemd":
        command => "/bin/systemctl daemon-reload && /bin/systemctl enable natlas.service && /bin/systemctl start natlas.service",
        refreshonly => true,
    }

    file { "/etc/nginx/sites-available/natlas":
        path => '/etc/nginx/sites-available/natlas',
        ensure => present,
        source => "puppet:///modules/natlasserver/natlas.nginx",
    }

    file { "/etc/nginx/sites-enabled/natlas":
        path => '/etc/nginx/sites-enabled/natlas',
        ensure => 'link',
        target => '/etc/nginx/sites-available/natlas',
    }

    file { "/etc/nginx/sites-enabled/default":
        path => '/etc/nginx/sites-enabled/default',
        ensure => 'link',
        target => '/etc/nginx/sites-available/natlas',
        notify => Exec["nginx-start"],
    }

    exec { "nginx-start":
        command => "/bin/systemctl reload nginx.service && /bin/systemctl enable nginx.service && /bin/systemctl start nginx.service",
        refreshonly => true,
    }

}
