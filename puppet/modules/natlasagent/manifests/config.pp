# Copyright (c) 2022, Oracle and/or its affiliates.

class natlasagent::config {

    exec { 'download-natlas-agent':
        command => "/bin/mkdir -p /opt/natlas && /usr/bin/curl https://github.com/natlas/natlas/releases/download/v0.5.4/natlas-agent-0.5.4.tgz -L -o /opt/natlas/natlas-agent.tgz",
        creates => '/opt/natlas/natlas-agent.tgz',
        notify => Exec["untar-natlas-agent"],
    }

    exec { 'untar-natlas-agent':
        command => "/bin/tar -zxf natlas-agent.tgz",
        cwd => "/opt/natlas",
        creates => "/opt/natlas/natlas-agent",
        require => Exec["download-natlas-agent"],
    }

    exec { "setup-agent":
        cwd => "/opt/natlas/natlas-agent",
        command => "/bin/bash setup-agent.sh",
        require => Exec["untar-natlas-agent"],
    }

    file { "/etc/systemd/system/natlas-agent.service":
        path => '/etc/systemd/system/natlas-agent.service',
        owner => 'root',
        group => 'root',
        mode => '600',
        ensure => present,
        source => "puppet:///modules/natlasagent/natlas-agent.service",
        notify => Exec["natlas-agent"],
    }

    exec { "natlas-agent":
        command => "/bin/systemctl daemon-reload && /bin/systemctl enable natlas-agent.service && /bin/systemctl start natlas-agent.service",
        refreshonly => true,
    }
}
