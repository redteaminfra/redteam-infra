# Copyright (c) 2022, Oracle and/or its affiliates.

class basetools::packages {
    $packages = ['screen',
                 'tmux',
                 'python3-pip',
    ]
    package { $packages: ensure => "installed" }
}
