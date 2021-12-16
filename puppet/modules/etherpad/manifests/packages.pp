class etherpad::packages {

    $packages = ['gzip',
                'libssl-dev',
                'pkg-config',
                'build-essential']

    package { $packages: ensure => "installed"}
}

