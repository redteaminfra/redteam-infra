# Copyright (c) 2026, Oracle and/or its affiliates.
"""Dormant, read-only one-host DigitalOcean identity observation.

The caller supplies reviewed core routing, a bound manifest and durable audit
callbacks. This service neither discovers hosts nor changes chain state.
"""

from __future__ import annotations

import ipaddress
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Mapping
from uuid import UUID, uuid4

from app.core.command_environment import barragan_subprocess_env
from app.services.provider_keyed_digitalocean_attachment import ExpectedDigitalOceanNode
from app.services.provider_keyed_gated_runner import (
    CommandAuditResult, CommandIntent, CommandResult, StartedCommand,
    UnreapedGatedCommandError, _private_scratch_path, run_gated_command,
)
from app.services.provider_keyed_host_binding import _digest_json, _regular_file_digest
from app.services.provider_keyed_initial_bootstrap import _sketch_file_snapshot
from app.services.sketch_bootstrap import (
    SketchBootstrapSpec, render_strict_v2_sketch_identity_ssh_config,
)
from app.services.sketch_ssh_keys import write_existing_sketch_ssh_key_files


_ID = re.compile(r"[1-9][0-9]*\Z")
_FIREWALL_OUTPUT_LIMIT = 65536
_FIREWALL_TOTAL_LIMIT = 262144
_FIREWALL_SNAPSHOT_SECONDS = 300
_FIREWALL_COMMANDS = (
    ("ufw_status_verbose", ("/usr/bin/sudo", "-n", "/usr/sbin/ufw", "status", "verbose")),
    ("ufw_defaults", ("/usr/bin/sudo", "-n", "/usr/bin/cat", "/etc/default/ufw")),
    ("ufw_configuration", ("/usr/bin/sudo", "-n", "/usr/bin/cat", "/etc/ufw/ufw.conf")),
    ("ufw_user_rules", ("/usr/bin/sudo", "-n", "/usr/bin/cat", "/etc/ufw/user.rules")),
    ("ufw_user6_rules", ("/usr/bin/sudo", "-n", "/usr/bin/cat", "/etc/ufw/user6.rules")),
    ("ufw_before_rules", ("/usr/bin/sudo", "-n", "/usr/bin/cat", "/etc/ufw/before.rules")),
    ("ufw_after_rules", ("/usr/bin/sudo", "-n", "/usr/bin/cat", "/etc/ufw/after.rules")),
    ("ufw_before6_rules", ("/usr/bin/sudo", "-n", "/usr/bin/cat", "/etc/ufw/before6.rules")),
    ("ufw_after6_rules", ("/usr/bin/sudo", "-n", "/usr/bin/cat", "/etc/ufw/after6.rules")),
    ("iptables_save", ("/usr/bin/sudo", "-n", "/usr/sbin/iptables-save")),
    ("ip6tables_save", ("/usr/bin/sudo", "-n", "/usr/sbin/ip6tables-save")),
    ("nft_ruleset", ("/usr/bin/sudo", "-n", "/usr/sbin/nft", "-j", "list", "ruleset")),
    ("ufw_version", ("/usr/bin/sudo", "-n", "/usr/sbin/ufw", "version")),
    ("iptables_version", ("/usr/bin/sudo", "-n", "/usr/sbin/iptables", "--version")),
    ("ip6tables_version", ("/usr/bin/sudo", "-n", "/usr/sbin/ip6tables", "--version")),
    ("nft_version", ("/usr/bin/sudo", "-n", "/usr/sbin/nft", "--version")),
)
_FIREWALL_OPTIONAL_FILES = (
    ("ufw_before_init", "/etc/ufw/before.init"),
    ("ufw_after_init", "/etc/ufw/after.init"),
    ("ufw_sysctl", "/etc/ufw/sysctl.conf"),
)
_FIREWALL_REMOTE_SCRIPT = (
    "import json, os, selectors, signal, stat, subprocess, time, uuid\n"
    "COMMANDS = " + repr(tuple((name, argv[2:]) for name, argv in _FIREWALL_COMMANDS)) + "\n"
    "OPTIONAL_FILES = " + repr(_FIREWALL_OPTIONAL_FILES) + "\n"
    "def boot():\n"
    "    with open('/proc/sys/kernel/random/boot_id', encoding='ascii') as stream:\n"
    "        return str(uuid.UUID(stream.read(128).strip()))\n"
    "def process_identity(pid):\n"
    "    with open('/proc/%d/stat' % pid, encoding='ascii') as stream:\n"
    "        raw = stream.read()\n"
    "    tail = raw[raw.rfind(')') + 2:].split()\n"
    "    return int(tail[2]), int(tail[19])\n"
    "def live_group_members(pid, start_ticks):\n"
    "    if process_identity(pid) != (pid, start_ticks):\n"
    "        raise ValueError('firewall process group identity changed')\n"
    "    members = set()\n"
    "    for entry in os.listdir('/proc'):\n"
    "        if not entry.isdigit():\n"
    "            continue\n"
    "        try:\n"
    "            with open('/proc/%s/stat' % entry, encoding='ascii') as stream:\n"
    "                raw = stream.read()\n"
    "        except FileNotFoundError:\n"
    "            continue\n"
    "        tail = raw[raw.rfind(')') + 2:].split()\n"
    "        if int(tail[2]) == pid and tail[0] != 'Z':\n"
    "            members.add(int(entry))\n"
    "    return members\n"
    "def read(name, argv):\n"
    "    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,\n"
    "                               stderr=subprocess.PIPE, start_new_session=True,\n"
    "                               env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})\n"
    "    selector = selectors.DefaultSelector()\n"
    "    output = bytearray()\n"
    "    errors = bytearray()\n"
    "    deadline = time.monotonic() + 15\n"
    "    reaped = False\n"
    "    start_ticks = None\n"
    "    try:\n"
    "        group_id, start_ticks = process_identity(process.pid)\n"
    "        if group_id != process.pid:\n"
    "            raise ValueError('firewall command is not group leader')\n"
    "        selector.register(process.stdout, selectors.EVENT_READ, output)\n"
    "        selector.register(process.stderr, selectors.EVENT_READ, errors)\n"
    "        while selector.get_map():\n"
    "            if time.monotonic() >= deadline:\n"
    "                raise ValueError('firewall command timed out')\n"
    "            for key, _ in selector.select(min(0.2, max(0, deadline - time.monotonic()))):\n"
    "                part = os.read(key.fd, 8192)\n"
    "                if not part:\n"
    "                    selector.unregister(key.fileobj)\n"
    "                else:\n"
    "                    key.data.extend(part)\n"
    "                    if len(output) > 65536 or len(errors) > 0:\n"
    "                        raise ValueError('firewall command output exceeded bound')\n"
    "        while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:\n"
    "            if time.monotonic() >= deadline:\n"
    "                raise ValueError('firewall command leader timed out')\n"
    "            time.sleep(0.02)\n"
    "        if live_group_members(process.pid, start_ticks):\n"
    "            raise ValueError('firewall command retained descendants')\n"
    "        exit_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))\n"
    "        reaped = True\n"
    "        if exit_code != 0 or not output:\n"
    "            raise ValueError('firewall command failed or was empty')\n"
    "        return output.decode('utf-8', 'strict')\n"
    "    except BaseException:\n"
    "        if not reaped:\n"
    "            if start_ticks is None or process_identity(process.pid) != (process.pid, start_ticks):\n"
    "                process.kill()\n"
    "                process.wait(timeout=2)\n"
    "                raise ValueError('firewall process group cannot be safely cancelled')\n"
    "            try:\n"
    "                try:\n"
    "                    os.killpg(process.pid, signal.SIGKILL)\n"
    "                except ProcessLookupError:\n"
    "                    if live_group_members(process.pid, start_ticks):\n"
    "                        raise ValueError('firewall process group remains active')\n"
    "                cleanup_deadline = time.monotonic() + 2\n"
    "                while live_group_members(process.pid, start_ticks):\n"
    "                    if time.monotonic() >= cleanup_deadline:\n"
    "                        raise ValueError('firewall process group did not quiesce')\n"
    "                    time.sleep(0.02)\n"
    "            finally:\n"
    "                process.wait(timeout=2)\n"
    "        raise\n"
    "    finally:\n"
    "        selector.close()\n"
    "        process.stdout.close()\n"
    "        process.stderr.close()\n"
    "def read_optional(path):\n"
    "    try:\n"
    "        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)\n"
    "    except FileNotFoundError:\n"
    "        return ['absent', None, None, None, None]\n"
    "    with os.fdopen(descriptor, 'rb') as stream:\n"
    "        before = os.fstat(stream.fileno())\n"
    "        if not stat.S_ISREG(before.st_mode):\n"
    "            raise ValueError('UFW optional input is not regular')\n"
    "        raw = stream.read(65537)\n"
    "        if len(raw) > 65536 or stream.read(1):\n"
    "            raise ValueError('UFW optional input exceeded bound')\n"
    "        after = os.fstat(stream.fileno())\n"
    "        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,\n"
    "                before.st_ctime_ns, before.st_uid, before.st_gid,\n"
    "                stat.S_IMODE(before.st_mode)) != (\n"
    "                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,\n"
    "                after.st_ctime_ns, after.st_uid, after.st_gid,\n"
    "                stat.S_IMODE(after.st_mode)):\n"
    "            raise ValueError('UFW optional input changed during read')\n"
    "        return ['present', raw.decode('utf-8', 'strict'),\n"
    "                before.st_uid, before.st_gid, stat.S_IMODE(before.st_mode)]\n"
    "started = time.monotonic()\n"
    "first_boot, first_time = boot(), time.time_ns()\n"
    "outputs = []\n"
    "total = 0\n"
    "for name, argv in COMMANDS:\n"
    "    value = read(name, argv)\n"
    "    total += len(value.encode('utf-8'))\n"
    "    if total > 262144 or time.monotonic() - started > 300:\n"
    "        raise ValueError('firewall snapshot exceeded total bound')\n"
    "    outputs.append([name, value])\n"
    "files = []\n"
    "for name, path in OPTIONAL_FILES:\n"
    "    status, value, uid, gid, mode = read_optional(path)\n"
    "    if status == 'present':\n"
    "        total += len(value.encode('utf-8'))\n"
    "    if total > 262144 or time.monotonic() - started > 300:\n"
    "        raise ValueError('firewall snapshot exceeded total bound')\n"
    "    files.append([name, path, status, value, uid, gid, mode])\n"
    "last_boot, last_time = boot(), time.time_ns()\n"
    "if first_boot != last_boot or last_time < first_time or time.monotonic() - started > 300:\n"
    "    raise ValueError('firewall snapshot crossed boot or time boundary')\n"
    "print(json.dumps({'boot_id': first_boot, 'started_at_ns': first_time,\n"
    "                  'completed_at_ns': last_time, 'commands': outputs, 'files': files},\n"
    "                 sort_keys=True, separators=(',', ':')))\n"
)
_REMOTE_SCRIPT = """import json, socket, urllib.request
base = 'http://169.254.169.254/metadata/v1/'
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
def read(name):
    url = base + name
    with opener.open(url, timeout=2) as response:
        if response.status != 200 or response.geturl() != url:
            raise ValueError('metadata endpoint changed')
        value = bytearray()
        while len(value) <= 128:
            part = response.read(129 - len(value))
            if not part:
                break
            value.extend(part)
        if not value or len(value) > 128 or not value.strip():
            raise ValueError('metadata body is missing or oversized')
        return bytes(value).decode('ascii').strip()
with open('/proc/sys/kernel/random/boot_id', encoding='ascii') as stream:
    boot_id = stream.read(128).strip()
print(json.dumps({'id': read('id'), 'region': read('region'),
                  'public_ipv4': read('interfaces/public/0/ipv4/address'),
                  'hostname': socket.gethostname(), 'boot_id': boot_id}, sort_keys=True))
"""

_HOST_SURFACE_SCRIPT = """import glob, ipaddress, json, os, pwd, re, stat, subprocess, sys, time, uuid
source = sys.argv[1]
if str(ipaddress.IPv4Address(source)) != source:
    raise ValueError('selected predecessor is not canonical IPv4')
target = sys.argv[2]
if str(ipaddress.IPv4Address(target)) != target:
    raise ValueError('selected target is not canonical IPv4')
parts = sys.argv[3].split()
if len(parts) != 4:
    raise ValueError('SSH connection context is missing or ambiguous')
client, client_port, local, local_port = parts
if (str(ipaddress.IPv4Address(client)) != source
        or str(ipaddress.IPv4Address(local)) != target
        or not client_port.isascii() or not client_port.isdecimal()
        or not local_port.isascii() or not local_port.isdecimal()
        or str(int(client_port)) != client_port or str(int(local_port)) != local_port
        or not 1 <= int(client_port) <= 65535 or local_port != '22'):
    raise ValueError('SSH connection differs from selected route')
connection = [client, int(client_port), local, int(local_port)]
def boot():
    with open('/proc/sys/kernel/random/boot_id', encoding='ascii') as stream:
        return str(uuid.UUID(stream.read(128).strip()))
def checked(argv):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=15,
                            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    if result.returncode != 0 or result.stderr or not result.stdout or len(result.stdout) > 65536:
        raise ValueError('host read command is incomplete')
    return result.stdout.decode('utf-8', 'strict')
def private_file(path, limit=65536, with_changed_ns=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                or before.st_nlink != 1 or before.st_mode & 0o022):
            raise ValueError('SSH configuration input is unsafe')
        raw = os.read(descriptor, limit + 1)
        if len(raw) > limit or os.read(descriptor, 1):
            raise ValueError('SSH configuration input exceeded bound')
        after = os.fstat(descriptor)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns',
                  'st_uid', 'st_gid', 'st_mode')
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise ValueError('SSH configuration input changed')
        decoded = raw.decode('utf-8', 'strict')
        return [decoded, max(after.st_mtime_ns, after.st_ctime_ns)] if with_changed_ns else decoded
    finally:
        os.close(descriptor)
def private_directory(path):
    info = os.lstat(path)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or info.st_mode & 0o022):
        raise ValueError('SSH configuration directory is unsafe')
    return [path, max(info.st_mtime_ns, info.st_ctime_ns)]
def configuration():
    root = '/etc/ssh/sshd_config'
    raw_root, root_changed_ns = private_file(root, with_changed_ns=True)
    paths = [root]
    for line in raw_root.splitlines():
        active = line.split('#', 1)[0].strip()
        if not active:
            continue
        if '\\\\' in active:
            raise ValueError('SSH configuration continuation is unproved')
        fields = active.split()
        if fields[0].lower() == 'include':
            if fields != ['Include', '/etc/ssh/sshd_config.d/*.conf']:
                raise ValueError('SSH Include is outside bounded graph')
            included = sorted(glob.glob('/etc/ssh/sshd_config.d/*.conf'))
            if len(included) > 16:
                raise ValueError('SSH Include graph exceeded bound')
            paths.extend(included)
    if len(paths) != len(set(paths)):
        raise ValueError('SSH Include graph duplicated input')
    rows = []
    total = 0
    for path in paths:
        if path != root and (not re.fullmatch(r'/etc/ssh/sshd_config\\.d/[A-Za-z0-9_.-]+\\.conf', path)
                             or os.path.islink(path)):
            raise ValueError('SSH Include path differs')
        raw, changed_ns = ([raw_root, root_changed_ns] if path == root else
                           private_file(path, with_changed_ns=True))
        total += len(raw.encode('utf-8'))
        if total > 131072:
            raise ValueError('SSH Include graph exceeded byte bound')
        for line in raw.splitlines():
            active = line.split('#', 1)[0].strip()
            if not active:
                continue
            if '\\\\' in active:
                raise ValueError('SSH configuration continuation is unproved')
            fields = active.split()
            if fields[0].lower() == 'include' and not (path == root and fields ==
                    ['Include', '/etc/ssh/sshd_config.d/*.conf']):
                raise ValueError('SSH nested or unknown Include is unproved')
            if fields[0].lower() == 'match' and any(field.lower() == 'rdomain' for field in fields[1:]):
                raise ValueError('SSH Match RDomain is unproved')
        rows.append([path, raw, changed_ns])
    return rows
def daemon():
    fields = ('MainPID', 'ActiveState', 'SubState', 'ExecStart', 'EnvironmentFiles',
              'Environment', 'FragmentPath', 'DropInPaths')
    service = checked(('/usr/bin/systemctl', 'show', 'ssh.service',
                       *('-p', fields[0]), *sum((('-p', item) for item in fields[1:]), ())))
    values = {}
    for line in service.splitlines():
        key, separator, value = line.partition('=')
        if not separator or key in values:
            raise ValueError('SSH service property differs')
        values[key] = value
    if set(values) != set(fields) or values['ActiveState'] != 'active':
        raise ValueError('SSH service is not fully active')
    pid_text = values['MainPID']
    if not pid_text.isdecimal() or int(pid_text) < 2:
        raise ValueError('SSH MainPID differs')
    pid = int(pid_text)
    with open('/proc/%d/stat' % pid, encoding='ascii') as stream:
        process_stat = stream.read(4096)
    process_fields = process_stat[process_stat.rfind(')') + 2:].split()
    if len(process_fields) < 20 or not process_fields[19].isdecimal():
        raise ValueError('SSH daemon process identity differs')
    start_ticks = int(process_fields[19])
    with open('/proc/%d/cmdline' % pid, 'rb') as stream:
        cmdline = stream.read(4097)
    if not cmdline or len(cmdline) > 4096 or not cmdline.endswith(b'\\x00'):
        raise ValueError('SSH daemon cmdline differs')
    executable = os.readlink('/proc/%d/exe' % pid)
    if executable != '/usr/sbin/sshd':
        raise ValueError('SSH daemon executable differs')
    environment, environment_changed_ns = private_file('/etc/default/ssh', 8192, True)
    fragment = values['FragmentPath']
    if fragment not in ('/usr/lib/systemd/system/ssh.service', '/lib/systemd/system/ssh.service'):
        raise ValueError('SSH service unit path differs')
    unit, unit_changed_ns = private_file(fragment, 16384, True)
    with open('/proc/stat', encoding='ascii') as stream:
        boot_lines = stream.read(65536).splitlines()
    boot_values = [line.split() for line in boot_lines if line.startswith('btime ')]
    if len(boot_values) != 1 or len(boot_values[0]) != 2 or not boot_values[0][1].isdecimal():
        raise ValueError('SSH daemon birth clock differs')
    boot_epoch_s = int(boot_values[0][1])
    clock_ticks_per_second = os.sysconf('SC_CLK_TCK')
    if boot_epoch_s <= 0 or type(clock_ticks_per_second) is not int or clock_ticks_per_second <= 0:
        raise ValueError('SSH daemon birth clock differs')
    birth_wall_ns = boot_epoch_s * 1000000000 + start_ticks * 1000000000 // clock_ticks_per_second
    configuration_rows = configuration()
    directory_rows = [private_directory('/etc/ssh'),
                      private_directory('/etc/ssh/sshd_config.d')]
    latest_input_ns = max(environment_changed_ns, unit_changed_ns,
                          *(row[2] for row in configuration_rows),
                          *(row[1] for row in directory_rows))
    if birth_wall_ns <= latest_input_ns + 2000000000:
        raise ValueError('SSH daemon predates loaded inputs')
    socket = checked(('/usr/bin/systemctl', 'show', 'ssh.socket',
                      '-p', 'ActiveState', '-p', 'Listen'))
    return {'service': values, 'socket': socket, 'pid': pid, 'start_ticks': start_ticks,
            'boot_epoch_s': boot_epoch_s, 'clock_ticks_per_second': clock_ticks_per_second,
            'birth_wall_ns': birth_wall_ns,
            'cmdline': [part for part in cmdline.decode('utf-8', 'strict').split('\\x00')[:-1]
                        if part],
            'exe': executable, 'environment_file': environment,
            'environment_changed_ns': environment_changed_ns,
            'unit_file': [fragment, unit, unit_changed_ns],
            'directory_changed_ns': directory_rows,
            'configuration': configuration_rows}
def account(name):
    row = pwd.getpwnam(name)
    home = row.pw_dir
    directory = os.path.join(home, '.ssh')
    for path in (home, directory):
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, row.pw_uid) or info.st_mode & 0o022:
            raise ValueError('account key path is unsafe')
    path = os.path.join(directory, 'authorized_keys')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid not in (0, row.pw_uid) or before.st_mode & 0o022):
            raise ValueError('account key file is unsafe')
        raw = os.read(fd, 65537)
        if len(raw) > 65536 or os.read(fd, 1):
            raise ValueError('account key file exceeded bound')
        after = os.fstat(fd)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_uid', 'st_gid', 'st_mode')
        if any(getattr(before, field) != getattr(after, field) for field in fields):
            raise ValueError('account key file changed')
        return [name, raw.decode('utf-8', 'strict'), before.st_uid, before.st_gid,
                stat.S_IMODE(before.st_mode)]
    finally:
        os.close(fd)
def alternate_key_absence(name):
    row = pwd.getpwnam(name)
    home = row.pw_dir
    directory = os.path.join(home, '.ssh')
    parents = []
    for path in (home, directory):
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, row.pw_uid) or info.st_mode & 0o022:
            raise ValueError('alternate key parent is unsafe')
        parents.append((info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                        stat.S_IMODE(info.st_mode), info.st_mtime_ns, info.st_ctime_ns))
    try:
        os.lstat(os.path.join(directory, 'authorized_keys2'))
    except FileNotFoundError:
        pass
    else:
        raise ValueError('alternate authorized key path exists')
    return tuple(parents)
first_boot, started = boot(), time.time_ns()
daemon_before = daemon()
alternate_before = {name: alternate_key_absence(name) for name in ('user', 'sketchssh')}
accounts = [account(name) for name in ('user', 'sketchssh')]
effective = []
for name in ('user', 'sketchssh'):
    # OpenSSH uses the address for Match Host when UseDNS is disabled.
    context = 'user=' + name + ',addr=' + client + ',host=' + client + ',laddr=' + local + ',lport=' + local_port
    value = checked(('/usr/sbin/sshd', '-T', '-C', context))
    if value.splitlines().count('usedns no') != 1:
        raise ValueError('SSH Match Host context is not address-only')
    effective.append([name, value])
listeners = checked(('/usr/bin/ss', '-H', '-lntuap'))
alternate_after = {name: alternate_key_absence(name) for name in ('user', 'sketchssh')}
if alternate_before != alternate_after:
    raise ValueError('alternate authorized key parent changed during collection')
daemon_after = daemon()
if daemon_before != daemon_after:
    raise ValueError('SSH daemon or configuration changed during collection')
last_boot, completed = boot(), time.time_ns()
if first_boot != last_boot or completed < started:
    raise ValueError('host surface crossed boot or time boundary')
print(json.dumps({'boot_id': first_boot, 'started_at_ns': started,
                  'completed_at_ns': completed, 'predecessor_ipv4': source,
                  'ssh_connection': connection,
                  'accounts': accounts, 'effective_sshd': effective,
                  'ssh_proof_version': 1, 'ssh_proof': daemon_before,
                  'alternate_authorized_keys_absent': ['user', 'sketchssh'],
                  'listeners': listeners}, sort_keys=True, separators=(',', ':')))
"""


class ProviderKeyedHostIdentityProbeError(ValueError):
    """Strict route or one-host metadata identity could not be proved."""


class ProviderKeyedHostIdentityCleanupUnprovedError(ProviderKeyedHostIdentityProbeError):
    """Probe scratch key/config cleanup failed after proven process quiescence."""


@dataclass(frozen=True)
class DigitalOceanHostIdentityEvidence:
    manifest_sha256: str
    chain_id: str
    terraform_address: str
    provider_instance_id: str
    region: str
    public_ipv4: str
    hostname: str
    boot_id: str
    ssh_alias: str
    invocation_id: str
    core_known_hosts_sha256: str
    sketch_known_hosts_sha256: str


@dataclass(frozen=True)
class DigitalOceanProbeScratchIntent:
    manifest_sha256: str
    chain_id: str
    terraform_address: str
    scratch_path: str


@dataclass(frozen=True)
class RawFirewallCommandEvidence:
    name: str
    sha256: str
    byte_count: int
    raw_output: str = field(repr=False)


@dataclass(frozen=True)
class RawFirewallFileEvidence:
    name: str
    path: str
    status: str
    sha256: str | None
    byte_count: int
    uid: int | None
    gid: int | None
    mode: int | None
    raw_output: str | None = field(repr=False)


@dataclass(frozen=True)
class DigitalOceanRawFirewallEvidence:
    """Bounded private raw observation only; no firewall policy is interpreted."""
    identity: DigitalOceanHostIdentityEvidence
    invocation_id: str
    boot_id: str
    started_at_ns: int
    completed_at_ns: int
    commands: tuple[RawFirewallCommandEvidence, ...] = field(repr=False)
    files: tuple[RawFirewallFileEvidence, ...] = field(repr=False)
    omitted_inputs: tuple[str, ...] = ()
    policy_interpreted: bool = False


@dataclass(frozen=True)
class DigitalOceanRawHostSurfaceEvidence:
    """Private, bounded account/effective-sshd/listener capture; no interpretation."""
    identity: DigitalOceanHostIdentityEvidence
    invocation_id: str
    boot_id: str
    started_at_ns: int
    completed_at_ns: int
    predecessor_ipv4: str
    ssh_connection: tuple[str, int, str, int] = field(repr=False)
    accounts: tuple[tuple[str, str, int, int, int], ...] = field(repr=False)
    effective_sshd: tuple[tuple[str, str], ...] = field(repr=False)
    listeners_raw: str = field(repr=False)
    policy_interpreted: bool = False
    alternate_authorized_keys_absent: tuple[str, ...] = ()
    ssh_proof_version: int | None = None
    ssh_proof: dict[str, object] | None = field(default=None, repr=False)


@dataclass(frozen=True)
class DigitalOceanRawHostCollection:
    """Temporally bracketed raw evidence; Match RDomain remains uninterpreted."""
    identity: DigitalOceanHostIdentityEvidence
    firewall_before: DigitalOceanRawFirewallEvidence = field(repr=False)
    surface: DigitalOceanRawHostSurfaceEvidence = field(repr=False)
    firewall_after: DigitalOceanRawFirewallEvidence = field(repr=False)
    policy_interpreted: bool = False


def _stable_firewall_commands(commands: tuple[RawFirewallCommandEvidence, ...]) -> tuple[tuple[str, str], ...]:
    """Ignore observation-time counters while retaining the exact raw captures."""
    stable = []
    for item in commands:
        output = item.raw_output
        if item.name in {"iptables_save", "ip6tables_save"}:
            lines = []
            for line in output.splitlines():
                if line.startswith(("# Generated by ", "# Completed on ")):
                    continue
                if line.startswith(":"):
                    line = re.sub(r"\[[0-9]+:[0-9]+\]", "[counter]", line)
                lines.append(line)
            output = "\n".join(lines)
        elif item.name == "nft_ruleset":
            try:
                output = json.dumps(_without_nft_packet_counters(json.loads(output)),
                                    sort_keys=True, separators=(",", ":"))
            except (TypeError, ValueError):
                # Invalid JSON is never granted an equivalence exception.
                pass
        stable.append((item.name, output))
    return tuple(stable)


def _without_nft_packet_counters(value):
    if isinstance(value, list):
        return [_without_nft_packet_counters(item) for item in value]
    if isinstance(value, dict):
        return {
            key: ({counter_key: _without_nft_packet_counters(counter_value)
                   for counter_key, counter_value in item.items()
                   if counter_key not in {"packets", "bytes"}}
                  if key == "counter" and isinstance(item, dict)
                  else _without_nft_packet_counters(item))
            for key, item in value.items()
        }
    return value


def collect_digitalocean_middle_host_evidence(**probe_kwargs) -> DigitalOceanRawHostCollection:
    result = probe_digitalocean_middle_identity(**probe_kwargs, _collect_host_surface=True)
    if not isinstance(result, DigitalOceanRawHostCollection):
        raise ProviderKeyedHostIdentityProbeError("middle host collection is incomplete")
    return result


def collect_digitalocean_edge_host_evidence(**probe_kwargs) -> DigitalOceanRawHostCollection:
    result = probe_digitalocean_edge_identity(**probe_kwargs, _collect_host_surface=True)
    if not isinstance(result, DigitalOceanRawHostCollection):
        raise ProviderKeyedHostIdentityProbeError("edge host collection is incomplete")
    return result


def collect_digitalocean_edge_firewall_evidence(**probe_kwargs) -> DigitalOceanRawFirewallEvidence:
    """Opt-in raw snapshot; it does not interpret firewall policy or readiness."""
    result = probe_digitalocean_edge_identity(**probe_kwargs, _collect_firewall=True)
    if not isinstance(result, DigitalOceanRawFirewallEvidence):
        raise ProviderKeyedHostIdentityProbeError("raw firewall collection is incomplete")
    return result


def collect_digitalocean_middle_firewall_evidence(**probe_kwargs) -> DigitalOceanRawFirewallEvidence:
    """Collect the same raw snapshot over the selected middle's strict user route."""
    result = probe_digitalocean_middle_identity(**probe_kwargs, _collect_firewall=True)
    if not isinstance(result, DigitalOceanRawFirewallEvidence):
        raise ProviderKeyedHostIdentityProbeError("raw firewall collection is incomplete")
    return result


def probe_digitalocean_middle_identity(**probe_kwargs) -> DigitalOceanHostIdentityEvidence | DigitalOceanRawFirewallEvidence:
    """Observe only the selected middle through homebase and its proxy."""
    return probe_digitalocean_edge_identity(**probe_kwargs, _selected_role="middle")


def probe_digitalocean_edge_identity(
    *, manifest: Mapping[str, object], manifest_sha256: str,
    chain_id: str, expected: ExpectedDigitalOceanNode,
    ssh_spec: SketchBootstrapSpec, reviewed_core_route: Mapping[str, str],
    sketch_known_hosts_sha256: str,
    scratch_path: Path, fence: Callable[[], None],
    scratch_intent_callback: Callable[[DigitalOceanProbeScratchIntent], None],
    intent_callback: Callable[[CommandIntent], None],
    started_callback: Callable[[StartedCommand], None],
    heartbeat_callback: Callable[[StartedCommand], None],
    result_callback: Callable[[CommandAuditResult], None],
    runner: Callable = run_gated_command,
    ssh_executable: Path = Path("/usr/bin/ssh"),
    admin_key_materializer: Callable = write_existing_sketch_ssh_key_files,
    _collect_firewall: bool = False,
    _collect_host_surface: bool = False,
    _selected_role: str = "edge",
) -> DigitalOceanHostIdentityEvidence | DigitalOceanRawFirewallEvidence | DigitalOceanRawHostCollection:
    """Observe one manifest-selected Sketch host through its pinned user alias."""
    key_dir = None
    config_path = None
    retain_scratch = False
    try:
        if (_selected_role not in {"middle", "edge"}
                or not isinstance(manifest, Mapping) or manifest.get("schema") != "provider-keyed-v2"
                or not isinstance(expected, ExpectedDigitalOceanNode)
                or not isinstance(chain_id, str) or not chain_id
                or _digest_json(dict(manifest)) != manifest_sha256):
            raise ValueError("bound manifest differs")
        nodes = manifest.get("nodes")
        policies = manifest.get("hostPolicies")
        if not isinstance(nodes, list) or not isinstance(policies, list):
            raise ValueError("bound route is incomplete")
        chain_rows = [row for row in nodes if isinstance(row, dict) and row.get("chainId") == chain_id]
        target_rows = [row for row in chain_rows if row.get("role") == _selected_role
                       and row.get("terraformAddress") == expected.address]
        middle_rows = [row for row in chain_rows if row.get("role") == "middle"]
        selected = [row for row in policies if isinstance(row, dict) and row.get("chainId") == chain_id]
        if (len(target_rows) != 1 or len(middle_rows) != 1 or len(selected) != 1
                or len({row.get("terraformAddress") for row in chain_rows}) != len(chain_rows)
                or target_rows[0].get("providerInstanceId") != expected.droplet_id
                or target_rows[0].get("name") != expected.name
                or target_rows[0].get("region") != expected.region
                or target_rows[0].get("publicIp") != expected.public_ipv4
                or middle_rows[0].get("name") != ssh_spec.middle.name
                or middle_rows[0].get("publicIp") != ssh_spec.middle.public_ip
                or not _ID.fullmatch(str(middle_rows[0].get("providerInstanceId")))
                or not isinstance(middle_rows[0].get("region"), str)
                or not str(middle_rows[0].get("terraformAddress", "")).startswith(
                    'digitalocean_droplet.middle["')
                or (_selected_role == "middle" and (
                    expected.name != ssh_spec.middle.name
                    or expected.public_ipv4 != ssh_spec.middle.public_ip))
                or (_selected_role == "edge" and sum(
                    edge.name == expected.name and edge.public_ip == expected.public_ipv4
                    for edge in ssh_spec.edges) != 1)
                or selected[0].get("proxyEgressIp") != ssh_spec.proxy.host_key_alias
                or selected[0].get("hosts") != ssh_spec.host_policies
                or not _ID.fullmatch(expected.droplet_id)
                or not isinstance(reviewed_core_route, Mapping)
                or dict(reviewed_core_route) != {
                    "homebasePublicIp": ssh_spec.homebase.host,
                    "homebaseUser": ssh_spec.homebase.user,
                    "proxyPrivateIp": ssh_spec.proxy.host,
                    "proxyPublicIp": ssh_spec.proxy.host_key_alias,
                    "proxyUser": ssh_spec.proxy.user,
                    "coreSshKeyPath": ssh_spec.homebase.ssh_private_key_path,
                }
                or ssh_spec.proxy.ssh_private_key_path != ssh_spec.homebase.ssh_private_key_path):
            raise ValueError("selected Sketch route differs from bound state")
        engagement_id = manifest.get("engagementId")
        if not isinstance(engagement_id, str) or not engagement_id:
            raise ValueError("bound engagement identity is unavailable")
        core_path = Path(ssh_spec.pinned_core_known_hosts_path)
        sketch_path = Path(ssh_spec.initial_sketch_known_hosts_path)
        if (str(core_path) != manifest.get("coreKnownHostsPath")
                or str(sketch_path) != manifest.get("sketchKnownHostsPath")
                or core_path == sketch_path
                or not isinstance(sketch_known_hosts_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", sketch_known_hosts_sha256)):
            raise ValueError("bound trust files differ")
        alias = f"barragan-bootstrap-user-{expected.name}"
        executable = Path(ssh_executable)
        if (not executable.is_absolute() or executable.is_symlink()
                or executable.resolve(strict=True) != executable
                or not executable.is_file() or not os.access(executable, os.X_OK)):
            raise ValueError("SSH executable is unavailable")
        scratch = _private_scratch_path(scratch_path)
        fence()
        core_before = _regular_file_digest(core_path, require_content=True)
        sketch_before = _sketch_file_snapshot(sketch_path)
        if (core_before != manifest.get("coreKnownHostsSha256")
                or sketch_before[2] != sketch_known_hosts_sha256):
            raise ValueError("known-hosts digest differs")
        _require_pinned_aliases(core_path, (ssh_spec.homebase.host, ssh_spec.proxy.host_key_alias))
        sketch_aliases = (f"barragan-bootstrap-sketch-{ssh_spec.middle.name}",)
        if _selected_role == "edge":
            sketch_aliases += (f"barragan-bootstrap-sketch-{expected.name}",)
        _require_pinned_aliases(sketch_path, sketch_aliases)
        fence()
        scratch_intent_callback(DigitalOceanProbeScratchIntent(
            manifest_sha256, chain_id, expected.address, str(scratch)))
        fence()
        key_dir = scratch / "keys"
        admin_private, _admin_public = admin_key_materializer(engagement_id, key_dir)
        admin_private = Path(admin_private)
        key_dir_stat = key_dir.stat()
        private_stat = admin_private.stat()
        if (key_dir.is_symlink() or key_dir.resolve(strict=True) != key_dir
                or not stat.S_ISDIR(key_dir_stat.st_mode) or key_dir_stat.st_uid != os.getuid()
                or stat.S_IMODE(key_dir_stat.st_mode) != 0o700
                or admin_private.is_symlink() or admin_private.parent != key_dir
                or not stat.S_ISREG(private_stat.st_mode) or private_stat.st_uid != os.getuid()
                or private_stat.st_nlink != 1 or stat.S_IMODE(private_stat.st_mode) != 0o600):
            raise ValueError("staged administration key is unsafe")
        config_text = render_strict_v2_sketch_identity_ssh_config(
            replace(ssh_spec, admin_private_key_path=str(admin_private)))
        # The proof command has no Ansible timeout wrapper. Bound every hop,
        # including ProxyJump's separate SSH clients, before first contact.
        if config_text.count("  ConnectTimeout 15") != config_text.count("Host "):
            raise ValueError("strict SSH route lacks a bounded hop")
        config_text = config_text.replace(
            "  ConnectTimeout 15", "  ConnectTimeout 15\n  ServerAliveInterval 10\n  ServerAliveCountMax 3")
        if (f"Host {alias}\n" not in config_text
                or "StrictHostKeyChecking accept-new" in config_text
                or "ControlMaster no" not in config_text
                or "ControlPersist no" not in config_text):
            raise ValueError("strict SSH route was not rendered")
        config_path = scratch / f"identity-ssh-{uuid4().hex}.conf"
        fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            config_bytes = config_text.encode()
            offset = 0
            while offset < len(config_bytes):
                written = os.write(fd, config_bytes[offset:])
                if written <= 0:
                    raise OSError("strict SSH config write was incomplete")
                offset += written
            os.fsync(fd)
            config_stat = os.fstat(fd)
            if (not stat.S_ISREG(config_stat.st_mode) or config_stat.st_uid != os.getuid()
                    or config_stat.st_nlink != 1 or stat.S_IMODE(config_stat.st_mode) != 0o600):
                raise ValueError("strict SSH config is unsafe")
        finally:
            os.close(fd)
        command = [str(executable), "-F", str(config_path), alias,
                   "python3", "-c", _quoted_remote_script()]
        recorded_intent = None
        recorded_start = None
        recorded_result = None

        def on_intent(value: CommandIntent) -> None:
            nonlocal recorded_intent
            fence()
            if recorded_intent is not None or value.scratch_path != str(scratch):
                raise ValueError("probe command intent differs")
            intent_callback(value)
            recorded_intent = value

        def on_started(value: StartedCommand) -> None:
            nonlocal recorded_start
            fence()
            if recorded_intent is None or recorded_start is not None or value.intent != recorded_intent:
                raise ValueError("probe command start differs")
            started_callback(value)
            recorded_start = value

        def on_heartbeat(value: StartedCommand) -> None:
            fence()
            if value != recorded_start or recorded_result is not None:
                raise ValueError("probe command heartbeat differs")
            heartbeat_callback(value)

        def on_result(value: CommandAuditResult) -> None:
            nonlocal recorded_result
            fence()
            if recorded_start is None or recorded_result is not None or value.started != recorded_start:
                raise ValueError("probe command result differs")
            result_callback(value)
            recorded_result = value

        fence()
        outcome = runner(command, scratch_path=scratch, intent_callback=on_intent,
                         started_callback=on_started, heartbeat_callback=on_heartbeat,
                         result_callback=on_result, provider_keyed_v2=True,
                         env=barragan_subprocess_env())
        fence()
        if (not isinstance(outcome, CommandResult) or recorded_start is None or recorded_result is None
                or outcome.started != recorded_start or outcome.returncode != recorded_result.returncode
                or outcome.returncode != 0 or outcome.stdout_truncated
                or len(outcome.stdout.encode()) > 4096):
            raise ValueError("probe command did not complete with bounded evidence")
        if (_regular_file_digest(core_path, require_content=True) != core_before
                or _sketch_file_snapshot(sketch_path) != sketch_before):
            raise ValueError("known-hosts file changed during probe")
        data = json.loads(outcome.stdout)
        if (not isinstance(data, dict)
                or set(data) != {"id", "region", "public_ipv4", "hostname", "boot_id"}
                or any(not isinstance(value, str) or not value for value in data.values())
                or data["id"] != expected.droplet_id or data["region"] != expected.region
                or data["public_ipv4"] != expected.public_ipv4
                or data["hostname"] != expected.name
                or ipaddress.ip_address(data["public_ipv4"]).version != 4):
            raise ValueError("host metadata differs from provider identity")
        boot_id = str(UUID(data["boot_id"]))
        if boot_id != data["boot_id"].lower():
            raise ValueError("host boot identity is invalid")
        identity_evidence = DigitalOceanHostIdentityEvidence(
            manifest_sha256, chain_id, expected.address, expected.droplet_id,
            expected.region, expected.public_ipv4, expected.name, boot_id,
            alias, recorded_intent.invocation_id, core_before, sketch_before[2],
        )
        if not _collect_firewall and not _collect_host_surface:
            return identity_evidence
        firewall_before = _collect_raw_firewall(
            identity_evidence, executable, config_path, alias, scratch,
            core_path, core_before, sketch_path, sketch_before, fence,
            intent_callback, started_callback, heartbeat_callback, result_callback, runner,
        )
        if not _collect_host_surface:
            return firewall_before
        predecessor = ssh_spec.proxy_egress_ip if _selected_role == "middle" else ssh_spec.middle.public_ip
        if _selected_role == "middle" and predecessor != ssh_spec.proxy.host_key_alias:
            raise ValueError("selected proxy egress differs from pinned route")
        surface = _collect_raw_host_surface(
            identity_evidence, predecessor, executable, config_path, alias, scratch,
            core_path, core_before, sketch_path, sketch_before, fence,
            intent_callback, started_callback, heartbeat_callback, result_callback, runner,
        )
        firewall_after = _collect_raw_firewall(
            identity_evidence, executable, config_path, alias, scratch,
            core_path, core_before, sketch_path, sketch_before, fence,
            intent_callback, started_callback, heartbeat_callback, result_callback, runner,
        )
        if (surface.boot_id != identity_evidence.boot_id
                or firewall_before.boot_id != firewall_after.boot_id
                or firewall_before.boot_id != surface.boot_id
                or not firewall_before.completed_at_ns <= surface.started_at_ns
                or not surface.completed_at_ns <= firewall_after.started_at_ns
                or firewall_after.completed_at_ns - firewall_before.started_at_ns
                   > _FIREWALL_SNAPSHOT_SECONDS * 1_000_000_000
                or _stable_firewall_commands(firewall_before.commands)
                != _stable_firewall_commands(firewall_after.commands)
                or [(row.name, row.status, row.sha256, row.byte_count, row.uid, row.gid, row.mode)
                    for row in firewall_before.files]
                != [(row.name, row.status, row.sha256, row.byte_count, row.uid, row.gid, row.mode)
                    for row in firewall_after.files]):
            raise ValueError("host policy changed during bounded collection")
        return DigitalOceanRawHostCollection(identity_evidence, firewall_before, surface, firewall_after)
    except UnreapedGatedCommandError:
        retain_scratch = True
        raise
    except Exception as exc:
        raise ProviderKeyedHostIdentityProbeError("strict DigitalOcean host identity is unproved") from exc
    finally:
        if not retain_scratch:
            try:
                if config_path is not None and (config_path.exists() or config_path.is_symlink()):
                    if config_path.is_symlink():
                        raise OSError("probe SSH config path changed")
                    config_path.unlink()
                if key_dir is not None and (key_dir.exists() or key_dir.is_symlink()):
                    if key_dir.is_symlink():
                        raise OSError("probe key directory changed")
                    shutil.rmtree(key_dir)
                if ((config_path is not None and (config_path.exists() or config_path.is_symlink()))
                        or (key_dir is not None and (key_dir.exists() or key_dir.is_symlink()))):
                    raise OSError("probe scratch cleanup is incomplete")
            except OSError as exc:
                raise ProviderKeyedHostIdentityCleanupUnprovedError(
                    "probe scratch cleanup is unproved"
                ) from exc


def _quoted_remote_script() -> str:
    import shlex
    return shlex.quote(_REMOTE_SCRIPT)


def _collect_raw_firewall(
    identity: DigitalOceanHostIdentityEvidence, executable: Path, config_path: Path,
    alias: str, scratch: Path, core_path: Path, core_digest: str,
    sketch_path: Path, sketch_snapshot: tuple, fence: Callable[[], None],
    intent_callback: Callable[[CommandIntent], None],
    started_callback: Callable[[StartedCommand], None],
    heartbeat_callback: Callable[[StartedCommand], None],
    result_callback: Callable[[CommandAuditResult], None], runner: Callable,
    *, expected_stderr: str = "",
) -> DigitalOceanRawFirewallEvidence:
    """Use one supervised SSH command for the fixed remote read-only snapshot."""
    import shlex

    if (_regular_file_digest(core_path, require_content=True) != core_digest
            or _sketch_file_snapshot(sketch_path) != sketch_snapshot):
        raise ValueError("known-hosts file changed before firewall collection")
    command = [str(executable), "-F", str(config_path), alias, "/usr/bin/sudo", "-n",
               "/usr/bin/python3", "-I", "-B", "-c", shlex.quote(_FIREWALL_REMOTE_SCRIPT)]
    intent = None
    started = None
    audit = None
    controller_started = time.monotonic()

    def on_intent(value: CommandIntent) -> None:
        nonlocal intent
        fence()
        if (intent is not None or value.scratch_path != str(scratch)
                or value.invocation_id == identity.invocation_id):
            raise ValueError("firewall snapshot intent differs")
        intent_callback(value)
        intent = value

    def on_started(value: StartedCommand) -> None:
        nonlocal started
        fence()
        if intent is None or started is not None or value.intent != intent:
            raise ValueError("firewall snapshot start differs")
        started_callback(value)
        started = value

    def on_heartbeat(value: StartedCommand) -> None:
        fence()
        if (value != started or audit is not None
                or time.monotonic() - controller_started > 330):
            raise ValueError("firewall snapshot heartbeat differs")
        heartbeat_callback(value)

    def on_result(value: CommandAuditResult) -> None:
        nonlocal audit
        fence()
        if started is None or audit is not None or value.started != started:
            raise ValueError("firewall snapshot result differs")
        result_callback(value)
        audit = value

    fence()
    outcome = runner(command, scratch_path=scratch, intent_callback=on_intent,
                     started_callback=on_started, heartbeat_callback=on_heartbeat,
                     result_callback=on_result, provider_keyed_v2=True,
                     max_output_bytes=1048576, env=barragan_subprocess_env())
    fence()
    if (not isinstance(outcome, CommandResult) or intent is None or started is None
            or audit is None or outcome.started != started
            or outcome.returncode != 0 or audit.returncode != 0
            or outcome.stdout_truncated or outcome.stderr_truncated
            or audit.stdout_truncated or audit.stderr_truncated
            or not outcome.stdout or outcome.stderr not in ("", expected_stderr)
            or audit.stderr_bytes != len(outcome.stderr.encode("utf-8"))
            or audit.stdout_bytes != len(outcome.stdout.encode("utf-8"))
            or audit.stdout_bytes > 1048576 or "\ufffd" in outcome.stdout
            or time.monotonic() - controller_started > 330):
        raise ValueError("firewall snapshot is incomplete or unbounded")
    if (_regular_file_digest(core_path, require_content=True) != core_digest
            or _sketch_file_snapshot(sketch_path) != sketch_snapshot):
        raise ValueError("known-hosts file changed during firewall collection")
    parsed = json.loads(outcome.stdout)
    if (not isinstance(parsed, dict)
            or set(parsed) != {"boot_id", "started_at_ns", "completed_at_ns", "commands", "files"}
            or str(UUID(parsed["boot_id"])) != identity.boot_id
            or type(parsed["started_at_ns"]) is not int
            or type(parsed["completed_at_ns"]) is not int
            or parsed["started_at_ns"] <= 0
            or parsed["completed_at_ns"] < parsed["started_at_ns"]
            or parsed["completed_at_ns"] - parsed["started_at_ns"]
            > _FIREWALL_SNAPSHOT_SECONDS * 1_000_000_000
            or not isinstance(parsed["commands"], list)
            or len(parsed["commands"]) != len(_FIREWALL_COMMANDS)
            or not isinstance(parsed["files"], list)
            or len(parsed["files"]) != len(_FIREWALL_OPTIONAL_FILES)):
        raise ValueError("firewall snapshot envelope differs")
    collected = []
    total = 0
    for (expected_name, _), row in zip(_FIREWALL_COMMANDS, parsed["commands"]):
        if (not isinstance(row, list) or len(row) != 2 or row[0] != expected_name
                or not isinstance(row[1], str) or not row[1] or "\ufffd" in row[1]):
            raise ValueError("firewall snapshot command coverage differs")
        raw = row[1]
        size = len(raw.encode("utf-8"))
        total += size
        if size > _FIREWALL_OUTPUT_LIMIT or total > _FIREWALL_TOTAL_LIMIT:
            raise ValueError("firewall snapshot exceeds raw output bound")
        collected.append(RawFirewallCommandEvidence(
            expected_name, hashlib.sha256(raw.encode("utf-8")).hexdigest(), size, raw,
        ))
    files = []
    for (expected_name, expected_path), row in zip(_FIREWALL_OPTIONAL_FILES, parsed["files"]):
        if (not isinstance(row, list) or len(row) != 7
                or row[:2] != [expected_name, expected_path]
                or row[2] not in {"present", "absent"}
                or (row[2] == "absent" and row[3:] != [None, None, None, None])
                or (row[2] == "present" and (
                    not isinstance(row[3], str) or "\ufffd" in row[3]
                    or any(type(value) is not int or value < 0 for value in row[4:])
                    or row[6] > 0o7777))):
            raise ValueError("optional UFW input coverage differs")
        raw = row[3]
        size = len(raw.encode("utf-8")) if raw is not None else 0
        total += size
        if size > _FIREWALL_OUTPUT_LIMIT or total > _FIREWALL_TOTAL_LIMIT:
            raise ValueError("optional UFW input exceeds raw output bound")
        files.append(RawFirewallFileEvidence(
            expected_name, expected_path, row[2],
            hashlib.sha256(raw.encode("utf-8")).hexdigest() if raw is not None else None,
            size, row[4], row[5], row[6], raw,
        ))
    return DigitalOceanRawFirewallEvidence(
        identity, intent.invocation_id, identity.boot_id, parsed["started_at_ns"],
        parsed["completed_at_ns"], tuple(collected), tuple(files),
    )


def _collect_raw_host_surface(
    identity: DigitalOceanHostIdentityEvidence, predecessor: str,
    executable: Path, config_path: Path, alias: str, scratch: Path,
    core_path: Path, core_digest: str, sketch_path: Path, sketch_snapshot: tuple,
    fence: Callable[[], None], intent_callback: Callable[[CommandIntent], None],
    started_callback: Callable[[StartedCommand], None],
    heartbeat_callback: Callable[[StartedCommand], None],
    result_callback: Callable[[CommandAuditResult], None], runner: Callable,
    *, expected_stderr: str = "",
) -> DigitalOceanRawHostSurfaceEvidence:
    """Collect exact account, effective SSH and listener inputs without publishing them."""
    import shlex

    if (str(ipaddress.IPv4Address(predecessor)) != predecessor
            or _regular_file_digest(core_path, require_content=True) != core_digest
            or _sketch_file_snapshot(sketch_path) != sketch_snapshot):
        raise ValueError("host surface route or pins changed")
    command = [str(executable), "-F", str(config_path), alias, "/usr/bin/sudo", "-n",
               "/usr/bin/python3", "-I", "-B", "-c", shlex.quote(_HOST_SURFACE_SCRIPT),
               shlex.quote(predecessor), shlex.quote(identity.public_ipv4),
               '"$SSH_CONNECTION"']
    intent = started = audit = None
    controller_started = time.monotonic()

    def on_intent(value: CommandIntent) -> None:
        nonlocal intent
        fence()
        if intent is not None or value.scratch_path != str(scratch):
            raise ValueError("host surface command intent differs")
        intent_callback(value)
        intent = value

    def on_started(value: StartedCommand) -> None:
        nonlocal started
        fence()
        if intent is None or started is not None or value.intent != intent:
            raise ValueError("host surface command start differs")
        started_callback(value)
        started = value

    def on_heartbeat(value: StartedCommand) -> None:
        fence()
        if value != started or audit is not None or time.monotonic() - controller_started > 90:
            raise ValueError("host surface command heartbeat differs")
        heartbeat_callback(value)

    def on_result(value: CommandAuditResult) -> None:
        nonlocal audit
        fence()
        if started is None or audit is not None or value.started != started:
            raise ValueError("host surface command result differs")
        result_callback(value)
        audit = value

    fence()
    outcome = runner(command, scratch_path=scratch, intent_callback=on_intent,
                     started_callback=on_started, heartbeat_callback=on_heartbeat,
                     result_callback=on_result, provider_keyed_v2=True,
                     max_output_bytes=262144, env=barragan_subprocess_env())
    fence()
    if (not isinstance(outcome, CommandResult) or intent is None or started is None or audit is None
            or outcome.started != started or outcome.returncode != 0 or audit.returncode != 0
            or outcome.stdout_truncated or outcome.stderr_truncated
            or audit.stdout_truncated or audit.stderr_truncated
            or outcome.stderr not in ("", expected_stderr)
            or audit.stderr_bytes != len(outcome.stderr.encode("utf-8")) or not outcome.stdout
            or len(outcome.stdout.encode("utf-8")) != audit.stdout_bytes
            or audit.stdout_bytes > 262144 or "\ufffd" in outcome.stdout
            or time.monotonic() - controller_started > 90
            or _regular_file_digest(core_path, require_content=True) != core_digest
            or _sketch_file_snapshot(sketch_path) != sketch_snapshot):
        raise ValueError("host surface collection is incomplete")
    payload = json.loads(outcome.stdout)
    old_fields = {"boot_id", "started_at_ns", "completed_at_ns",
                                "predecessor_ipv4", "ssh_connection", "accounts",
                                "effective_sshd", "listeners", "alternate_authorized_keys_absent"}
    proof_fields = {"ssh_proof_version", "ssh_proof"}
    has_proof = isinstance(payload, dict) and set(payload) == old_fields | proof_fields
    if (not isinstance(payload, dict)
            or set(payload) not in (old_fields, old_fields | proof_fields)
            or payload["boot_id"] != identity.boot_id
            or payload["predecessor_ipv4"] != predecessor
            or not isinstance(payload["ssh_connection"], list)
            or len(payload["ssh_connection"]) != 4
            or type(payload["started_at_ns"]) is not int or type(payload["completed_at_ns"]) is not int
            or not 0 < payload["started_at_ns"] <= payload["completed_at_ns"]
            or payload["completed_at_ns"] - payload["started_at_ns"] > 90_000_000_000
            or not isinstance(payload["accounts"], list) or len(payload["accounts"]) != 2
            or not isinstance(payload["effective_sshd"], list) or len(payload["effective_sshd"]) != 2
            or payload["alternate_authorized_keys_absent"] != ["user", "sketchssh"]
            or not isinstance(payload["listeners"], str) or not payload["listeners"]):
        raise ValueError("host surface envelope differs")
    proof = payload.get("ssh_proof") if has_proof else None
    if has_proof and (type(payload["ssh_proof_version"]) is not int
                      or payload["ssh_proof_version"] != 1 or type(proof) is not dict
                      or set(proof) != {"service", "socket", "pid", "start_ticks",
                                            "boot_epoch_s", "clock_ticks_per_second", "birth_wall_ns",
                                            "cmdline", "exe", "environment_file",
                                            "environment_changed_ns", "unit_file", "configuration",
                                            "directory_changed_ns"}
                      or len(json.dumps(proof).encode("utf-8")) > 160000):
        raise ValueError("versioned SSH proof envelope differs")
    connection = payload["ssh_connection"]
    if (type(connection[0]) is not str or connection[0] != predecessor
            or type(connection[1]) is not int or not 1 <= connection[1] <= 65535
            or type(connection[2]) is not str or connection[2] != identity.public_ipv4
            or type(connection[3]) is not int or connection[3] != 22):
        raise ValueError("host SSH connection differs from selected route")
    accounts = []
    for expected, row in zip(("user", "sketchssh"), payload["accounts"]):
        if (not isinstance(row, list) or len(row) != 5 or row[0] != expected
                or not isinstance(row[1], str) or not row[1] or len(row[1].encode()) > 65536
                or "\ufffd" in row[1]
                or any(type(value) is not int or value < 0 for value in row[2:])
                or row[4] > 0o7777):
            raise ValueError("account key capture differs")
        accounts.append(tuple(row))
    effective = []
    for expected, row in zip(("user", "sketchssh"), payload["effective_sshd"]):
        if (not isinstance(row, list) or len(row) != 2 or row[0] != expected
                or not isinstance(row[1], str) or not row[1]
                or len(row[1].encode()) > 65536 or "\ufffd" in row[1]):
            raise ValueError("effective SSH capture differs")
        effective.append(tuple(row))
    if len(payload["listeners"].encode()) > 65536 or "\ufffd" in payload["listeners"]:
        raise ValueError("listener capture differs")
    return DigitalOceanRawHostSurfaceEvidence(
        identity, intent.invocation_id, identity.boot_id,
        payload["started_at_ns"], payload["completed_at_ns"], predecessor,
        tuple(connection), tuple(accounts), tuple(effective), payload["listeners"],
        alternate_authorized_keys_absent=("user", "sketchssh"),
        ssh_proof_version=1 if has_proof else None, ssh_proof=proof,
    )


def _require_pinned_aliases(path: Path, aliases: tuple[str, ...]) -> None:
    for alias in aliases:
        result = subprocess.run(["/usr/bin/ssh-keygen", "-F", alias, "-f", str(path)],
                                capture_output=True, text=True, timeout=3, check=False)
        if result.returncode != 0 or not result.stdout.strip():
            raise ValueError("required SSH host key is not pinned")
