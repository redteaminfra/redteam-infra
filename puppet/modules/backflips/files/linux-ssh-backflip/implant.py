# Copyright (c) 2022, Oracle and/or its affiliates.

import sys, os, time, atexit, socket, subprocess
from signal import SIGTERM

import logging

fqdn = 'FQDN_PLACEHOLDER'
port = 'PORT_PLACEHOLDER'
keyfile = 'KEYFILE_PLACEHOLDER'

if __name__ == '__main__':
    try:
        pid = os.fork()
        if pid > 0:
            # exit first parent
            sys.exit(0)
    except OSError, e:
        sys.stderr.write('fork 1 failed: %d (%s)\n' % (e.errno, e.strerror))
        sys.exit(1)

    # decouple from parent environment
    os.chdir('/')
    os.setsid()
    os.umask(0)

    # do second fork
    try:
        pid = os.fork()
        if pid > 0:
            # exit from second parent
            sys.exit(0)
    except OSError, e:
        sys.stderr.write('fork 2 failed: %d (%s)\n' % (e.errno, e.strerror))
        sys.exit(1)

    # redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    si = file('/dev/null', 'r')
    so = file('/dev/null', 'a+')
    se = file('/dev/null', 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())


    # add the handlers to the logger
    logging.basicConfig(filename='/tmp/payload.log',level=logging.DEBUG)
    logging.debug('payload damonized my pid: %d' % os.getpid())

    options = [
        '-oServerAliveInterval=30',
        '-p2222',
        '-oServerAliveCountMax=5',
        '-oUserKnownHostsFile=/dev/null',
        '-oStrictHostKeyChecking=no',
        '-i %s' % keyfile,
        '-N', # Do not execute a remote command.  This is useful for just forwarding ports
        '-n', # Redirects stdin from /dev/null
        '-R %s:localhost:22' % port
    ]
    cmd='ssh ' + ' '.join(options) +  ' flip@%s' % fqdn
    logging.debug("cmd: \"%s\"" % cmd)
    while True:
        try:
            psx = 'ps x | grep ssh | grep "%s" | grep -v grep | wc -l' % fqdn
            proc = subprocess.Popen(psx, shell=True, stdout=subprocess.PIPE)
            (out, err) = proc.communicate()
            num = int(out.strip())
            logging.debug("num copies running: %d" % num)
            if num < 1:
                logging.debug("running ssh")
                proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                (out, err) = proc.communicate()
                logging.debug("ssh exited")
                logging.debug("ssh stderr: %s" % err)
                logging.debug("ssh sdout: %s" % out)
        except Exception as e:
            logging.debug("got an exception: %s" % e.message)
            pass
        logging.debug("sleeping for 60")
        time.sleep(60)
