class proxytools::packages {
    $packages = ['asciinema',
                 'screen',
                 'tmux',
                 'zile',
                 'emacs',
                 'nmap',
                 'nikto' ]
    package { $packages: ensure => "installed" }
}
