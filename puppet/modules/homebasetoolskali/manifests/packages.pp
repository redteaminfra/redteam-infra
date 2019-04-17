class homebasetools::packages {
    $packages = ['asciinema',
                 'xfce4',
                 'tigervnc-standalone-server',
                 'screen',
                 'tmux',
                 'zile',
                 'emacs25-nox',
                 'firefox-esr',
    ]
    package { $packages: ensure => "installed" }
}
