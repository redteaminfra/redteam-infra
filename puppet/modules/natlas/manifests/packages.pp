class natlas::packages {

    $packages = ['nginx', 'virtualenv', 'python3', 'python3-pip', 'python3-venv', 'nmap']
    package { $packages: ensure => "installed"}
   
}
