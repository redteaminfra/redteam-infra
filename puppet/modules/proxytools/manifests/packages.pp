# Copyright (c) 2022, Oracle and/or its affiliates.

class proxytools::packages {
    $packages = ['asciinema',
                 'zile',
                 'emacs',
                 'nmap',
                 'nikto',
                 'xclip',
                 'autossh']
    package { $packages: ensure => "installed" }
}
