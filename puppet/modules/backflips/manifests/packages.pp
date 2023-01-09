# Copyright (c) 2023, Oracle and/or its affiliates.

class backflips::packages {

    $packages = ['wamerican']

    package { $packages: ensure => "installed"}
}
