class homebasetoolsubuntu::packages {
    $packages = ['asciinema',
                 'xfce4',
                 'xfce4-goodies',
                 'tigervnc-standalone-server',
                 'tigervnc-viewer',
                 'screen',
                 'tmux',
                 'zile',
                 'emacs',
                 'firefox',
                 'nmap',
                 'nikto',
                 'proxychains4']
    package { $packages: ensure => "installed" }
}
