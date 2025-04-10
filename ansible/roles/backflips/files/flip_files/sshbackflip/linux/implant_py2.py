#! /usr/bin/env python
# Copyright (c) 2024, Oracle and/or its affiliates.

from __future__ import absolute_import
import logging
import os
import subprocess
import sys
import time
from io import open

fqdn = u'{{ FQDN_PLACEHOLDER }}'
port = u'{{ PORT_PLACEHOLDER }}'
keyfile = u'KEYFILE_PLACEHOLDER'
bport = u'{{ BACKFLIP_PORT }}'

if __name__ == u'__main__':
    try:
        pid = os.fork()
        if pid > 0:
            # exit first parent
            sys.exit(0)
    except OSError, e:
        sys.stderr.write(u'fork 1 failed: %d (%s)\n' % (e.errno, e.strerror))
        sys.exit(1)

    # decouple from parent environment
    os.chdir(u'/')
    os.setsid()
    os.umask(0)

    # do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # exit from second parent
            sys.exit(0)
    except OSError, e:
        sys.stderr.write(u'fork 2 failed: %d (%s)\n' % (e.errno, e.strerror))
        sys.exit(1)

    # redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    si = open(u'/dev/null', u'r')
    so = open(u'/dev/null', u'a+')
    se = open(u'/dev/null', u'a+')
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())

    # add the handlers to the logger
    logging.basicConfig(filename=u'/tmp/payload.log', level=logging.DEBUG)
    logging.debug(u'payload daemonized my pid: %d' % os.getpid())

    options = [
        u'-oServerAliveInterval=30',
        u'-p %s' % bport,
        u'-oServerAliveCountMax=5',
        u'-oUserKnownHostsFile=/dev/null',
        u'-oStrictHostKeyChecking=no',
        u'-i %s' % keyfile,
        u'-N',  # Do not execute a remote command.  This is useful for just forwarding ports
        u'-n',  # Redirects stdin from /dev/null
        u'-R %s:localhost:22' % port
    ]
    cmd = u'ssh ' + u' '.join(options) + u' flip@%s' % fqdn
    logging.debug(u"cmd: \"%s\"" % cmd)
    while True:
        try:
            psx = u'ps x | grep ssh | grep "%s" | grep -v grep | wc -l' % fqdn
            proc = subprocess.Popen(psx, shell=True, stdout=subprocess.PIPE)
            (out, err) = proc.communicate()
            num = int(out.strip())
            logging.debug(u"num copies running: %d" % num)
            if num < 1:
                logging.debug(u"running ssh")
                proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE)
                (out, err) = proc.communicate()
                logging.debug(u"ssh exited")
                logging.debug(u"ssh stderr: %s" % err)
                logging.debug(u"ssh stdout: %s" % out)
        except Exception, e:
            logging.debug(u"got an exception: %s" % e)
            pass
        logging.debug(u"sleeping for 60")
        time.sleep(60)
