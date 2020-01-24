class waybackdownloader {
    package { 'wayback_machine_downloader':
        ensure   => 'installed',
        provider => 'gem',
    }
}
