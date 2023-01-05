# Copyright (c) 2022, Oracle and/or its affiliates.

class yama {

  file { "/etc/sysctl.d/99-kill-ptrace.conf":
    path => "/etc/sysctl.d/99-kill-ptrace.conf",
    owner => 'root',
    group => 'root',
    mode => '644',
    ensure => present,
    source => "puppet:///modules/yama/99-kill-ptrace.conf",
    notify => Exec["sysctl"],
  }

  exec { "sysctl":
    command => "/sbin/sysctl -q --system",
    refreshonly => true,
  }

}
