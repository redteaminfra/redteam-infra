# The SSH Backflip

Backflips creates SSH-based reverse tunnels for victim access. In V2, the Python tooling owns listener containers directly. Ansible only prepares the runtime files and prerequisites.

## Runtime Model

Victim implants still connect outbound to a public callback host, and operators still connect back through the tunnel from the Backflips host. The listener runtime is now container-only:

- `backflip_<listener-id>` runs the hardened OpenSSH listener
- `autossh_<listener-id>` maintains the reverse forward through the middle proxy
- each listener gets its own Compose project and bridge network

The generated listener project lives at:

```text
/opt/backflips/containers/<listener-id>/docker-compose.yml
```

The canonical authorized keys file is:

```text
/opt/backflips/etc/authorized_keys
```

## Configuration

`etc/backflips.conf` keeps the defaults used by the CLI:

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

`middleIP` is required either in the file or on the command line. `middleUser` and `middleKeyPath` default to `sketchssh` and `/opt/ssh-proxy/keys/sketchkey`, but they may be overridden per listener.

## `sshbackflip.py`

The script still has two command groups:

- `backflip` manages victim records and payload generation
- `listener` manages listener containers and runtime config

Common listener operations:

```sh
sudo python3 sshbackflip.py listener add \
  --name finance \
  --callback-host finance.example.com \
  --middle-ip 198.51.100.20 \
  --port 2222

sudo python3 sshbackflip.py listener list

sudo python3 sshbackflip.py listener delete --name finance
```

`listener add` writes the Compose file, starts the containers, inspects the listener container IP, and stores the effective values in `etc/backflips.conf`. `listener delete` tears down that project before removing the config entry. `listener list` shows the saved config plus current container status.

## Faceplants

When a victim username is unknown, the payload intentionally leaks a locator string in the listener SSH logs. Use:

```sh
sudo python3 sshbackflip.py backflip check-faceplant
```

The command searches the managed listener container logs and offers to update the victim username in `etc/backflips_db`.

## Prerequisites And Migration

Docker and Compose must already be installed, the middle proxy must be reachable, and the SSH key at `middleKeyPath` must be readable.

Existing deployments that rely on a shared `/opt/backflips/docker-compose.yml` are not migrated automatically. Recreate those listeners explicitly with `listener add`.
