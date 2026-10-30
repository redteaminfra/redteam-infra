# Backflips_V2 Role

`backflips_v2` bootstraps the Backflips runtime on a host. It installs prerequisites through its Docker dependency, creates the `flip` account, copies the Backflips files into `/opt/backflips`, and ensures the canonical authorized keys file exists at `/opt/backflips/etc/authorized_keys`.

Listener orchestration is no longer an Ansible responsibility. After the role runs, operators use `sshbackflip.py listener ...` to create, inspect, and remove per-listener Docker Compose projects.

## Runtime Ownership

Ansible owns:

- installing Docker and Compose through the role dependency
- creating `/opt/backflips`
- copying the Backflips code and creating the initial config
- reconciling the default sketch transport key path without replacing listener sections
- creating `/opt/backflips/etc/authorized_keys`

`sshbackflip.py` owns:

- generating listener Docker Compose files
- starting and stopping listener containers
- discovering listener container IPs
- persisting listener runtime metadata in `etc/backflips.conf`

Re-running the role preserves the listener sections written by the CLI.

## Listener Topology

Each listener is its own Compose project under `/opt/backflips/containers/<listener-id>/docker-compose.yml`.

The generated project contains:

- `backflip_<listener-id>`: an `lscr.io/linuxserver/openssh-server:latest` listener container
- `autossh_<listener-id>`: an autossh sidecar that reverse forwards the public callback port through the middle proxy
- a dedicated bridge network for that listener only

The listener container mounts a writable, listener-specific `/config`
directory. At listener creation time the CLI copies in:

- the canonical `/opt/backflips/etc/authorized_keys`
- the packaged `sshd_config` from the Backflips codebase

This lets the container initialize its own files without granting it write
access to either canonical source. The CLI atomically propagates victim keys
from the canonical authorized-keys file to every managed listener.

## Configuration

The default `etc/backflips.conf` now includes middle-proxy settings:

```ini
[DEFAULT]
callbackHost = redteamexample.com
internalIP = 127.0.0.1
callbackPort = 2222
callbackUser = flip
baseDir = /opt/backflips/
middleIP =
middleUser = sketchssh
middleKeyPath = /opt/ssh-proxy/keys/sketchkey
```

`middleIP` must be set globally or passed on the listener command line.
`middleUser` and `middleKeyPath` can also be overridden per listener. The role
renders `middleKeyPath` from the `sketchkey` role variable and defaults to
`/opt/ssh-proxy/keys/sketchkey`.

On sketch nodes, the sketch playbook enables remote TCP forwarding and public
remote-forward binds only for the unprivileged `sketchssh` transport account.

## Example Playbook

```yaml
- hosts: proxies
  vars:
    sketchkey: /opt/ssh-proxy/keys/example-sketch
  roles:
    - backflips_v2
```

## Operator Workflow

```sh
sudo python3 /opt/backflips/sshbackflip.py listener add \
  --name finance \
  --callback-host finance.example.com \
  --middle-ip 198.51.100.20 \
  --port 2222

sudo python3 /opt/backflips/sshbackflip.py listener list

sudo python3 /opt/backflips/sshbackflip.py listener delete --name finance
```

Prerequisites after Ansible finishes:

- Docker and Compose must be available
- the configured middle proxy must be reachable
- the middle proxy SSH key must be readable at `middleKeyPath`

Existing deployments that use a shared `/opt/backflips/docker-compose.yml` are not migrated automatically. Those listeners must be recreated explicitly with `sshbackflip.py listener add`.

## Migrating from the previous public layout

The `backflips` role now contains the legacy implementation. The consolidated
`sshbackflip.py` interface and Docker Compose listener runtime live in
`backflips_v2`. Change playbooks that need that runtime to use `backflips_v2`
and review the configuration and listener setup above before deployment.
The roles share `/opt/backflips`; select one implementation per host. Back up
existing configuration, keys, and listener state before changing roles.
