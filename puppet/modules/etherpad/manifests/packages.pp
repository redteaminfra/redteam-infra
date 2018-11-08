class etherpad::packages {

    $packages = ['gzip',
                'libssl-dev',
                'pkg-config',
                'curl',
                'build-essential']

    package { $packages: ensure => "installed"}
}

