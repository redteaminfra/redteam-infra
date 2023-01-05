# Copyright (c) 2022, Oracle and/or its affiliates.

class monitoring::config {

  exec { "clone_elastalert":
      command => "/usr/bin/git clone https://github.com/Yelp/elastalert.git /etc/elastalert",
      creates => '/etc/elastalert',
      notify => Exec['pip_pyopenssl'],
  }

  exec { "pip_pyopenssl":
      command => "/usr/bin/pip install pyOpenSSL",
      notify => Exec['create_elastalert'],
      refreshonly => true,
  }

  exec { "create_elastalert":
      cwd => "/etc/elastalert",
      command => "/usr/bin/python setup.py install",
      refreshonly => true,
      notify => Exec['create_elastalert_rules'],
  }

  exec { "create_elastalert_rules":
      cwd => "/etc/elastalert",
      command => "/bin/mkdir -p /etc/elastalert/rules",
      refreshonly => true,
      notify => Exec['setup_elastalert_index'],
  }

  exec { "setup_elastalert_index":
    cwd => "/etc/elastalert",
    command => "/usr/local/bin/elastalert-create-index",
  }

  file { "/etc/elastalert/config.yaml":
    path => '/etc/elastalert/config.yaml',
    owner => 'root',
    group => 'root',
    mode => '660',
    ensure => present,
    source => "puppet:///modules/monitoring/config.yaml",
  }

  file { "/etc/elastalert/authFile.yaml":
	path => '/etc/elastalert/authFile.yaml',
	owner => 'root',
	group => 'root',
	mode => '660',
	ensure => present,
	source => "puppet:///modules/monitoring/authFile.yaml",
  }

  file { "/etc/elastalert/rules/C2Compromised.yaml":
    path => '/etc/elastalert/rules/C2Compromised.yaml',
    owner => 'root',
    group => 'root',
    mode => '660',
    ensure => present,
    source => "puppet:///modules/monitoring/C2Compromised.yaml",
  }

  file { "/etc/elastalert/rules/C2Dead.yaml":
    path => '/etc/elastalert/rules/C2Dead.yaml',
    owner => 'root',
    group => 'root',
    mode => '660',
    ensure => present,
    source => "puppet:///modules/monitoring/C2Dead.yaml",
  }

  file { "/etc/systemd/system/elastalert.service":
    path => '/etc/systemd/system/elastalert.service',
    owner => 'root',
    group => 'root',
    mode => '660',
    ensure => present,
    source => "puppet:///modules/monitoring/elastalert.service",
    notify => Exec["reload_elastalert"],
  }

  exec { "reload_elastalert":
    command => "/bin/systemctl daemon-reload && /bin/systemctl enable elastalert.service && /bin/systemctl start elastalert.service",
    refreshonly => true,
  }

}
