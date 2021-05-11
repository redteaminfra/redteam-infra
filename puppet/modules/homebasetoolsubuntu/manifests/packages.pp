class homebasetoolsubuntu::packages {
    $packages = ['asciinema',
                 'xfce4',
                 'xfce4-goodies',
                 'tigervnc-standalone-server',
                 'tigervnc-viewer',
                 'zile',
                 'emacs',
                 'firefox',
                 'nmap',
                 'nikto',
                 'xclip',
                 'proxychains4']
    package { $packages: ensure => "installed" }
}
