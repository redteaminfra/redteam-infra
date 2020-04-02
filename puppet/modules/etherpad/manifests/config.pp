class etherpad::config {

    user { 'etherpad':
        ensure => 'present',
        home => '/home/etherpad',
        uid => '337',
        shell => '/bin/bash',
        managehome => true
    }

    exec { "install_nodejs":
        command => "/usr/bin/curl -sL https://deb.nodesource.com/setup_13.x  | /bin/bash - && /usr/bin/apt install -y nodejs",
        notify => Exec["clone_etherpad"],
     }

    exec { "clone_etherpad":
        user => "etherpad",
        command => "/usr/bin/git clone https://github.com/ether/etherpad-lite.git /home/etherpad/etherpad",
        creates => '/home/etherpad/etherpad',
    }

    file { "/etc/systemd/system/etherpad.service":
        path => '/etc/systemd/system/etherpad.service',
        owner => 'root',
        group => 'root',
        mode => '600',
        ensure => present,
        source => "puppet:///modules/etherpad/etherpad.service",
        notify => Exec["reload-systemd-etherpad"],
    }

    exec { "reload-systemd-etherpad":
        command => "/bin/systemctl daemon-reload && /bin/systemctl enable etherpad.service && /bin/systemctl start etherpad.service",
    }
}
