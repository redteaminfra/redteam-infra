# Copyright (c) 2023, Oracle and/or its affiliates.

class nfsclient::packages {
  $packages = ['nfs-common']

  package { $packages: ensure => installed, }
}
