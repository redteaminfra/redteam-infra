class backflips::packages {

    $packages = ['wamerican']

    package { $packages: ensure => "installed"}
}
