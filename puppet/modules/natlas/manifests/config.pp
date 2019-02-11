class natlas::config {

    exec { "download-elastic-dpkg":
        command => "/usr/bin/wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-6.6.0.deb -O /tmp/elastic.deb && /usr/bin/dpkg -i /tmp/elastic.deb",
        notify => Exec["enable-elastic"],
        creates => '/tmp/elastic.deb',
        require => Package["default-jre"],
    }

    exec { "enable-elastic":
        command => "/bin/systemctl enable elasticsearch.service && /bin/systemctl start elasticsearch.service"
    }

    user { 'natlas':
        ensure => 'present',
        home => '/home/natlas',
        uid => '338',
        shell => '/bin/bash',
        managehome => true
    }

    exec { 'clone_natlas':
        command => "/usr/bin/git clone https://github.com/natlas/natlas /opt/natlas",
        creates => '/opt/natlas',
        require => Exec["download-elastic-dpkg"],
        notify => File["/opt/natlas"],
    }

    file { '/opt/natlas':
        mode => '0755',
        ensure => present,
        owner => 'natlas',
        group => 'natlas',
        recurse => 'true',
        require => Exec["clone_natlas"],
    }

    exec { "setup-server":
        cwd => "/opt/natlas/natlas-server",
        command => "/bin/bash setup-server.sh",
        require => Exec["clone_natlas"],
    }

    exec { "setup-agent":
        cwd => "/opt/natlas/natlas-agent",
        command => "/bin/bash setup-agent.sh",
        require => Exec["clone_natlas"],
    }

    file { "/etc/systemd/system/natlas.service":
        path => '/etc/systemd/system/natlas.service',
        owner => 'root',
        group => 'root',
        mode => '600',
        ensure => present,
        source => "puppet:///modules/natlas/natlas.service",
        notify => Exec["reload-systemd"],
    }

    exec { "reload-systemd":
        command => "/bin/systemctl daemon-reload && /bin/systemctl enable natlas.service && /bin/systemctl start natlas.service",
    }

    file { "/etc/nginx/sites-available/natlas":
        path => '/etc/nginx/sites-available/natlas',
        ensure => present,
        source => "puppet:///modules/natlas/natlas.nginx",
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
    }

    file { "/etc/systemd/system/natlas-agent.service":
        path => '/etc/systemd/system/natlas-agent.service',
        owner => 'root',
        group => 'root',
        mode => '600',
        ensure => present,
        source => "puppet:///modules/natlas/natlas-agent.service",
        notify => Exec["natlas-agent"],
    }

    exec { "natlas-agent":
        command => "/bin/systemctl daemon-reload && /bin/systemctl enable natlas-agent.service && /bin/systemctl start natlas-agent.service",
    }

}
