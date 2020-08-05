class sshproxy::config {

    $sshproxy_dirs = [ "/opt/sshproxy",
                      "/opt/sshproxy/keys" ]

    file { $sshproxy_dirs:
        owner => 'root',
        group => 'root',
        mode => '755',
        ensure => 'directory',
    }

    file { "/opt/sshproxy/install_proxy.py":
        path => "/opt/sshproxy/install_proxy.py",
        owner => 'root',
        group => 'root',
        mode => '644',
        ensure => present,
        source => "puppet:///modules/sshproxy/install_proxy.py",
    }

    file { "/opt/sshproxy/install_sketch.py":
        path => "/opt/sshproxy/install_sketch.py",
        owner => 'root',
        group => 'root',
        mode => '644',
        ensure => present,
        source => "puppet:///modules/sshproxy/install_sketch.py",
    }

    file { "/opt/sshproxy/provision_sketch.py":
        path => "/opt/sshproxy/provision_sketch.py",
        owner => 'root',
        group => 'root',
        mode => '644',
        ensure => present,
        source => "puppet:///modules/sshproxy/provision_sketch.py",
    }

    file { "/opt/sshproxy/README.md":
        path => "/opt/sshproxy/README.md",
        owner => 'root',
        group => 'root',
        mode => '644',
        ensure => present,
        source => "puppet:///modules/sshproxy/README.md",
    }

    exec { "rsa_keygen_rsa_sshproxy":
        command => "/usr/bin/ssh-keygen -f /opt/sshproxy/keys/sketchkey -N '' -t rsa",
        creates => ["/opt/sshproxy/keys/sketchkey",
                    "/opt/sshproxy/keys/sketchkey.pub"],
        require => File["/opt/sshproxy/keys"],
    }

    exec { "rsa_keygen_ed25519_sshproxy":
        command => "/usr/bin/ssh-keygen -f /opt/sshproxy/keys/sketchkey_ed25519 -N '' -t ed25519",
        creates => ["/opt/sshproxy/keys/sketchkey_ed25519",
                    "/opt/sshproxy/keys/sketchkey_ed25519.pub"],
         require => File["/opt/sshproxy/keys"],
    }
}
