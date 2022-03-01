class nfsserver::packages {
  $packages = ['nfs-kernel-server']

  package { $packages: ensure => "installed" }

}
