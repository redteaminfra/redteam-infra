class logstashconfig::packages {


  $packages = ['apt-transport-https',
              'logstash']

  package { $packages: ensure => "installed" }

}
