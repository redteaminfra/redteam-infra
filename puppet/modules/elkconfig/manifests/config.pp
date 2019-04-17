class elkconfig::config {

    file { '/etc/elasticsearch/elasticsearch.yml':
        path => '/etc/elasticsearch/elasticsearch.yml',
        ensure => 'present',
        owner => 'root',
        group => 'elasticsearch',
        source => "puppet:///modules/elkconfig/elasticsearch.yml",
        notify => Exec["reload-elasticsearch"],
    }

    exec { "reload-elasticsearch":
        command => "/bin/systemctl restart elasticsearch",
    }
}
