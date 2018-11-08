class nweb::packages {

    $packages = ['nginx', 'virtualenv', 'python3', 'python3-pip']
    package { $packages: ensure => "installed"}
   
}
