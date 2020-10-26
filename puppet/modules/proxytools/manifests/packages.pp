class proxytools::packages {
    $packages = ['asciinema',
                 'screen',
                 'tmux',
                 'zile',
                 'emacs',
                 'nmap',
                 'nikto',
                 'xclip',
                 'python3-pip',
                 'autossh']
    package { $packages: ensure => "installed" }
}
