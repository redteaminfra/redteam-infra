class homebasetoolsubuntu::packages {
    $packages = ['asciinema', 'xfce4', 'xfce4-goodies', 'tightvncserver', 'screen', 'tmux', 'zile', 'emacs', 'firefox', 'nmap', 'nikto', 'proxychains']
    package { $packages: ensure => "installed" }
}
