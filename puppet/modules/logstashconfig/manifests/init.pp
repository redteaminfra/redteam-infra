# Copyright (c) 2022, Oracle and/or its affiliates.

class logstashconfig {
    include logstashconfig::packages
    include logstashconfig::config
}
