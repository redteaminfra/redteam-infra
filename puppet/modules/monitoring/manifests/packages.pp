class monitoring::packages {
    $packages = ['python-pip', 'libffi-dev']
    package { $packages: ensure => "installed"}
}
