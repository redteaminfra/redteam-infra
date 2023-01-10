# Copyright (c) 2023, Oracle and/or its affiliates.

class openresty::packages {

    apt::source { 'open_resty':
        comment => 'Open_Resty_apt_Source',
        location => 'http://openresty.org/package/ubuntu',
        repos => 'main',
        release => 'focal',
        key => {
            server => 'pgp.mit.edu',
            source => 'https://openresty.org/package/pubkey.gpg',
            id => 'E52218E7087897DC6DEA6D6D97DB7443D5EDEB74'
        },
        include => {
            'deb' => true,
            'src' => true,
        },
        notify => Exec['apt_update'],
    }

    $packages = ['openresty',
                'libnginx-mod-http-headers-more-filter']

    package { $packages: ensure => "installed" }
}
