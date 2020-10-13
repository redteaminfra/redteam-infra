class logstashconfig::config {

  exec { "add_hostname_for_logstash":
    command => "/bin/bash -c 'echo hostname=$(hostname)' >> /etc/default/logstash",
    onlyif => "/usr/bin/test -f /etc/default/logstash",
    unless => "/bin/grep -q hostname /etc/default/logstash",
    notify => Exec["named_logstash"],
  }

  exec { "named_logstash" :
    command => "/bin/bash -c 'echo server=elk-$(hostname | cut -d - -f2- | tr -d \"\n\").infra.redteam' >> /etc/default/logstash",
    unless => "/bin/grep -q server /etc/default/logstash",
    refreshonly => true,
  }

  # this is so gross b/c the service file is actually created by a
  # puppetforge module and on kali, the service is wrong.  This
  # fixes an issue for both new and existing homebases.
  $service_file = "/etc/systemd/system/logstash.service"
  exec { "ensure_${service_file}_exist":
    command => "bash -c 'test -f ${service_file} && sed -i -e \"s/^Group=logstash/Group=adm/\" ${service_file}' && systemctl daemon-reload && systemctl restart logstash ;true",
    path    =>  ["/usr/bin","/usr/sbin", "/bin"],
    refreshonly => true,
  }
}
