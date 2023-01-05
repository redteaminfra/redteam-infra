# Copyright (c) 2022, Oracle and/or its affiliates.

class nfsclient::packages {
  $packages = ['nfs-common']

  package { $packages: ensure => installed, }
}
