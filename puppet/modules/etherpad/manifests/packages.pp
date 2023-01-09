# Copyright (c) 2023, Oracle and/or its affiliates.

class etherpad::packages {

    $packages = ['gzip',
                'libssl-dev',
                'pkg-config',
                'build-essential']

    package { $packages: ensure => "installed"}
}

