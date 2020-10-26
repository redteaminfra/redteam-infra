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
                 'python3-pip',
                 'xclip',
                 'proxychains4']
    package { $packages: ensure => "installed" }
}
