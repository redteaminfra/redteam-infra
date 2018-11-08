class nmap::config {

    exec { "download_nmap_source":
        command => "/usr/bin/wget https://nmap.org/dist/nmap-7.60.tar.bz2 -O /tmp/nmap.tar.bz2",
    	creates => '/tmp/nmap.tar.bz2',
		notify => Exec["extract_nmap"],
	}

    exec { "extract_nmap":
		cwd => "/tmp",
        command => "/bin/bash -c '/bin/bzip2 -cd nmap.tar.bz2 | /bin/tar xvf -'",
        refreshonly => true,
		notify => Exec["make_nmap"],
	}
    
	exec { "make_nmap":
		cwd => "/tmp/nmap-7.60",
        command => "/bin/bash -c './configure && make && make install'",
        refreshonly => true,
	}
}
