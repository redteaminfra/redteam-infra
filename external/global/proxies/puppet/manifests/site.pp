node "default" {
  include 'hostsexternal'
  include 'gitpuppet'
  include 'ssh'
  include 'dante'
  include 'volunteerssh'
  include 'unattendedupgrades'
  include 'yama'
  include 'nmap'
  include 'mollyguard'
  include 'basetools'
  include 'proxytools'
  #include 'tinyproxy'
  include 'sshproxy'
  include 'cleanup'
  include 'waybackdownloader'
  include 'cloudagent'
  include 'openresty'
  include 'sketchopsec'
  include 'logstashconfig'


  package { ['openjdk-8-jre-headless']:
  }
}
