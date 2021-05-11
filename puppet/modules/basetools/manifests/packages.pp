class basetools::packages {
    $packages = ['screen',
                 'tmux',
                 'python3-pip',
    ]
    package { $packages: ensure => "installed" }
}
