class sketchopsec::config {

    file { "/opt/sketch":
        owner => 'root',
        group => 'root',
        mode => '755',
        ensure => 'directory',
    }
    
    file { "/opt/sketch/sketch-setup.py":
        path => "/opt/sketch/sketch-setup.py",
        owner => 'root',
        group => 'root',
        mode => '644',
        ensure => present,
        source => "puppet:///modules/sketchopsec/sketch-setup.py",
    }

    file { "/opt/sketch/requirements.txt":
        path => "/opt/sketch/requirements.txt",
        owner => 'root',
        group => 'root',
        mode => '644',
        ensure => present,
        source => "puppet:///modules/sketchopsec/requirements.txt",
        notify => Exec["opsec-sketch-requirements"],
    }

    file { "/opt/sketch/sketch.json":
        path => "/opt/sketch/sketch.json",
        owner => 'root',
        group => 'root',
        mode => '644',
        ensure => present,
        source => "puppet:///modules/sketchopsec/sketch.json",
        notify => Exec["opsec-sketch-python"],
    }

    exec { "opsec-sketch-requirements":
        command => "/usr/bin/pip3 install -r /opt/sketch/requirements.txt",
        require => File["/opt/sketch/requirements.txt"],
        refreshonly => true,
    }

    exec { "opsec-sketch-python":
        command => "/usr/bin/python3 /opt/sketch/sketch-setup.py",
        require => Exec["opsec-sketch-requirements"],
        notify => Exec["save-iptables"],
        refreshonly => true,
        unless => "/usr/bin/pip3 show python-iptables",
    }

    exec { "save-iptables":
        command => "/bin/bash -c '/sbin/iptables-save > /etc/iptables/rules.v4'",
        require => File["/opt/sketch/sketch-setup.py"],
        refreshonly => true,
    }
}