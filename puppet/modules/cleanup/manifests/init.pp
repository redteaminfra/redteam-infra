class cleanup {
    tidy { "/var/lib/puppet/reports":
        age => "1d",
        recurse => true,
    }
}
