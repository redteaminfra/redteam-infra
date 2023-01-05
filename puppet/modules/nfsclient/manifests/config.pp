# Copyright (c) 2022, Oracle and/or its affiliates.

class nfsclient::config {
  file { '/dropbox':
    ensure => 'directory',
    owner => 'nobody',
    group => 'redteam',
    mode => '770',
  }

  mount { '/dropbox':
    ensure => 'mounted',
    atboot => true,
    device => '192.168.0.10:/dropbox',
    options => 'auto,rw,nofail,noatime,nolock,intr,tcp,actimeo=1800',
    fstype => 'nfs',
    remounts => false,
  }
}
