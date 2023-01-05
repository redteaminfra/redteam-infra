# Copyright (c) 2022, Oracle and/or its affiliates.

class logstashconfig::packages {


  $packages = ['apt-transport-https',
              'logstash']

  package { $packages: ensure => "installed" }

}
