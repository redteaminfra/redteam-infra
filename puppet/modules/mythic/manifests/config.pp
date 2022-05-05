class mythic::config {

    file { "/opt/Mythic":
        path => "/opt/Mythic",
        owner => 'root',
        group => 'root',
        mode => '755',
        ensure => 'directory',
    }

    exec { "download_mythic":
        command => "/usr/bin/curl -sL https://raw.githubusercontent.com/mattreduce/mythic-crate/7c0dc5968124229354a18e6fef4c9de52ef7a104/setup.sh > mythic-setup.sh",
        cwd => "/opt/",
        require => File["/opt/Mythic"],
        notify => Exec["install_mythic"],
     }

    exec { "install_mythic":
        command => "/usr/bin/yes | /bin/bash mythic-setup.sh",
        cwd => "/opt/",
        refreshonly => true,
        timeout => 0,
        require => Exec["download_mythic"],
    }
}
