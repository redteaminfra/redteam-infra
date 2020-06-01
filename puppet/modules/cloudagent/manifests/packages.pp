class cloudagent::packages {

    $packages = ['snapd']
    package { $packages: ensure => "installed"}
}
