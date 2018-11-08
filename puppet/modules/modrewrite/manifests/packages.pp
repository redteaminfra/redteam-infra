class modrewrite::packages {
 
	$packages = ['apache2']
    package { $packages: ensure => "installed" }
}
