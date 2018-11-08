#!/bin/bash

if [ ! -f ./update.jar ]; then
    cd /opt/cobaltstrike
fi

java -jar update.jar
