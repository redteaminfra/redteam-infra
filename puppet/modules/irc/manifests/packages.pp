class irc::packages {

    $packages = ['python', 'python3', 'irssi']
    package { $packages: ensure => "installed"}
}
