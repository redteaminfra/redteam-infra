class cobaltstrike::packages {
    $packages = ['default-jre', 'mingw-w64']
    package { $packages: ensure => "installed"}
}
