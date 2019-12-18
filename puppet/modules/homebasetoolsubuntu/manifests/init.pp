class homebasetoolsubuntu {
    include homebasetoolsubuntu::packages

    file { "/usr/local/bin/setup-xfce4-vnc":
      path => '/usr/local/bin/setup-xfce4-vnc',
      owner => 'root',
      mode => '755',
      ensure => present,
      source => "puppet:///modules/homebasetoolsubuntu/setup-xfce4-vnc"
    }

    file { "/usr/local/lib/dot_screensaver":
      path => '/usr/local/lib/dot_screensaver',
      owner => 'root',
      mode => '755',
      ensure => present,
      source => "puppet:///modules/homebasetoolsubuntu/dot_xscreensaver"
    }
}
