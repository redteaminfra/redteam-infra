class homebasetoolsubuntu::packages {
    $packages = ['asciinema', 'xfce4', 'xfce4-goodies', 'tightvncserver', 'screen', 'tmux', 'zile', 'emacs', 'firefox', 'nmap', 'nikto']
    package { $packages: ensure => "installed" }
}
