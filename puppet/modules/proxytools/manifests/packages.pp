class proxytools::packages {
    $packages = ['asciinema',
                 'zile',
                 'emacs',
                 'nmap',
                 'nikto',
                 'xclip',
                 'autossh']
    package { $packages: ensure => "installed" }
}
