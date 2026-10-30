# Copyright (c) 2026, Oracle and/or its affiliates.
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch, MagicMock

from test_helpers import host, configuration, IMAGE

class ReadinessTests(unittest.TestCase):
    def ready(self, *, socket=None, health=None, docker_ports=None, pid='42', raw_health=None, version='0.6.0'):
        config = configuration()
        config['version'] = version
        def resolve(path, *args, **kwargs):
            if str(path).startswith('/usr/local/'):
                return Path('/opt/atc/venv/bin') / path.name
            return path
        def command(argv, **kwargs):
            if argv[0] == 'systemctl':
                return 'MainPID='+pid+'\nUser=atc\nActiveState=active\n'
            if argv[0] == 'ss':
                return socket if socket is not None else 'LISTEN 0 2048 127.0.0.1:8790 0.0.0.0:* users:(("atc-api",pid=42,fd=7))\n'
            if argv[0] == 'docker':
                return '|'.join(json.dumps(v) for v in [IMAGE, {'io.atc.managed':'true','io.atc.release':version}, docker_ports if docker_ports is not None else {'5432/tcp':[{'HostIp':'127.0.0.1','HostPort':'15432'}]}, True, 'healthy'])
            raise AssertionError(argv)
        response = MagicMock()
        response.__enter__.return_value.read.return_value = raw_health if raw_health is not None else json.dumps(health if health is not None else {'status':'ok','version':version}).encode()
        opener = MagicMock(); opener.open.return_value=response
        with patch.object(host, 'protected', return_value=True), patch.object(Path, 'resolve', resolve), patch.object(Path, 'stat', return_value=SimpleNamespace(st_uid=500)), patch.object(host.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=500)), patch.object(host.os, 'access', return_value=True), patch.object(host, 'command', side_effect=command), patch.object(host.urllib.request, 'build_opener', return_value=opener):
            return host.ready(config)

    def test_actual_installer_shaped_local_readiness(self):
        self.assertTrue(self.ready())

    def test_061_readiness_requires_its_exact_release(self):
        self.assertTrue(self.ready(version='0.6.1'))
        self.assertFalse(self.ready(version='0.6.1', health={'status':'ok','version':'0.6.0'}))

    def test_foreign_or_public_or_duplicate_listener_refused(self):
        for socket in ['LISTEN 0 2048 127.0.0.1:8790 0.0.0.0:* users:(("other",pid=43,fd=7))',
                       'LISTEN 0 2048 0.0.0.0:8790 0.0.0.0:* users:(("atc-api",pid=42,fd=7))',
                       'malformed', '', 'one\ntwo']:
            with self.subTest(socket=socket): self.assertFalse(self.ready(socket=socket))

    def test_private_database_binding_required(self):
        self.assertFalse(self.ready(docker_ports={'5432/tcp':[{'HostIp':'0.0.0.0','HostPort':'15432'}]}))

    def test_bad_pid_or_health_does_not_claim_ready(self):
        self.assertFalse(self.ready(pid='0'))
        self.assertFalse(self.ready(pid='invalid'))
        self.assertFalse(self.ready(health={'status':'ok','version':'different'}))
        self.assertFalse(self.ready(raw_health=b'not-json'))
        self.assertFalse(self.ready(raw_health=b'x'*4097))

if __name__=='__main__': unittest.main()
