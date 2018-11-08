class loot {

    file {'/loot':
        ensure => 'directory',
        owner => 'root',
        group => 'root',
        mode => '1777',
    }
    
    file {'/loot/README.md':
        ensure => 'file',
        path => '/loot/README.md',
        owner => 'root',
        group => 'root',
        mode => '777',
        source => "puppet:///modules/loot/README.md",
        require => File["/loot"],
    }
    
    file {'/loot/TEMPLATE.md':
        ensure => 'file',
        path => '/loot/TEMPLATE.md',
        owner => 'root',
        group => 'root',
        mode => '777',
        source => "puppet:///modules/loot/TEMPLATE.md",
        require => File["/loot"],
    }
}
