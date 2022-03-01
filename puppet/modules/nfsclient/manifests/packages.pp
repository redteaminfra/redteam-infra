class nfsclient::packages {
  $packages = ['nfs-common']

  package { $packages: ensure => installed, }
}
