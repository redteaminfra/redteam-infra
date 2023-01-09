# Copyright (c) 2023, Oracle and/or its affiliates.

class cleanup {
    tidy { "/var/lib/puppet/reports":
        age => "1d",
        recurse => true,
    }
}
