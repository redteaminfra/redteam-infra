# Copyright (c) 2023, Oracle and/or its affiliates.

class homebasetools::packages {
    $packages = ['asciinema',
                 'xfce4',
                 'tigervnc-standalone-server',
                 'zile',
                 'emacs25-nox',
                 'firefox-esr',
    ]
    package { $packages: ensure => "installed" }
}
