class nmap::packages {
    $packages = ['gcc',
                'g++', 
                'make']
    package { $packages: ensure => "installed"}
}
