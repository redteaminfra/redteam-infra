class touch {

    exec { "testPuppet":
        command => "/usr/bin/touch /tmp/gitworks"
    }

}
