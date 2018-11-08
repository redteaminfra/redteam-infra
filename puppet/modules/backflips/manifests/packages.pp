class backflips::packages {

    $packages = ['autossh']

    package { $packages: ensure => "installed"}
}
