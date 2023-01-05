# Copyright (c) 2022, Oracle and/or its affiliates.

class cloudagent::packages {

    $packages = ['snapd']
    package { $packages: ensure => "installed"}
}
