class proxytools::packages {
    $packages = ['asciinema',
                 'screen',
                 'tmux',
                 'zile',
                 'emacs',
                 'nmap',
                 'nikto',
                 'xclip']
    package { $packages: ensure => "installed" }
}
