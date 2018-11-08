class hostsexternal::config {

    $vpc = generate("/bin/bash", "-c", "/bin/hostname | /usr/bin/cut -d '-' -f2- | tr -d '\n'")

    $subnet = generate("/bin/bash", "-c", "/bin/hostname -I | /usr/bin/cut -d. -f1-3 | tr -d '\n'")

    file { "/etc/hosts":
        path => '/etc/hosts',
        owner => 'root',
        group => 'root',
        mode => '644',
        ensure => present,
        content => template('hosts/hosts.erb'),
    }
}
