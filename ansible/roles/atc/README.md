# ATC native service

Installs one app-built ATC release on Homebase using the application's supported
`install.sh --non-interactive` or exact same-release `--repair` entrypoint. The
role does not copy ATC source into RTI or reimplement its migrations, identity
bootstrap or recovery journals. Contributions use Apache License 2.0.

**Supported contract:** Ubuntu 22.04 amd64, systemd and Python 3.10. Ubuntu 24.04
is refused before host changes because the current ATC installer explicitly
rejects it. No alternate interpreter or host downgrade is attempted. Role unit
and syntax checks are not native installation qualification; combined Barragan
Homebase acceptance and source-maintainer approval remain separate gates.

## Release compatibility

ATC 0.6.1 (`e9cda6c7ced6c828b619c30b68e24459708a3e16`) retains the 0.6.0
native installer/configuration contract and supported platform. Supply its own
app-built archive, exact SHA256, version and PostgreSQL digest; the role verifies
its migration identity from that archive. Do not reuse a 0.6.0 receipt or migration
identity: 0.6.1 adds migration 048. Source compatibility tests alone do not qualify
a release artifact or native installation. The role's existing fresh-host venv
and exact PostgreSQL caching prerequisites apply unchanged. Graph/inference
remain opt-in upstream workflows outside this baseline. Existing installations
still require a separately reviewed upgrade; this is fresh-install compatibility.

Verified archive: `atc-v0.6.1-linux-amd64.tar.gz`, 92,830,018 bytes,
SHA256 `92e53c669ddad370157019f6b818416950ae6577e6408d9c08e6350b53560cd0`.
The role verifier accepted all 195 members and their internal checksums, exact
source/version, PostgreSQL digest `bb3e1a57e5407e0a5280b4211980a5e537f4abd234a87014ac979849a78dd825`,
and migration identity `756a5bd00365082c1ccdbef18eaad61a8e7be05b1a8df7682e185da8fdf9c473`.
The same archive also completed a fresh installation through Barragan on its
Ubuntu22 Homebase. Broader application and preservation testing is separate;
this receipt does not claim those workflows were qualified.

## Source publication and artifact preparation

Publish this role's adapter code and metadata, not the application binary or
embedded wheelhouses. An administrator prepares the reviewed native archive on
the controller and supplies the exact inputs below. No public download URL is
required by the role, and it never downloads a substitute release. ATC source
and native releases remain owned by the application project. The current private
bundle's third-party redistribution inventory is not complete; its verified
checksum and first-party Apache license do not authorize public redistribution.

## Prerequisites and inputs

Run with privilege escalation and gathered facts. After OS, artifact, Python,
operator, path, retained-state, port and capacity preflight, a fresh host with no
Docker/containerd executable, socket, package, service unit or state/configuration
footprint installs Docker through RTI's existing `docker` role. An existing client
always skips that installer; its engine must already run Docker >=24 with Compose
>=2.20. Stopped, incompatible or partial installations require operator recovery;
this role does not upgrade or start them. Retained ATC with missing Docker is
also refused. At least 4GiB free beneath the installation and default Docker
storage is checked before dependency changes; app preflight rechecks its actual
storage. Unsupported Ubuntu24 and bad artifacts stop before Docker installation.
For a fresh install only, missing venv support on the Ubuntu distro Python
installs `python3.10-venv` with normal Ubuntu dependency resolution. No alternate
interpreter, symlink change or downgrade is attempted. A private temporary venv
must bootstrap pip successfully before Docker changes; retained installations
with missing support require operator recovery. Install the host's Git, OpenSSL,
util-linux, passwd, iproute2, GNU tar/coreutils/findutils/gawk and systemd tools
before applying. The exact PostgreSQL image must be cached or registry-accessible;
the role caches that exact digest only for fresh installs before invoking the
app installer, avoiding legacy registry-inspection incompatibilities. Cached
images are reused; no tag fallback or retained-runtime image change occurs.

| Input | Requirement/default |
| --- | --- |
| `atc_release_archive` | Absolute controller path to the app-built flat native `.tar.gz` bundle. A plain Git source archive is insufficient. |
| `atc_release_sha256` | Reviewed bundle's 64-character SHA256. |
| `atc_source_revision` | Exact full application commit in `release.env`. |
| `atc_release_version` | Exact bundle release version. |
| `atc_postgres_image` | Exact official `docker.io/library/postgres:16…@sha256:…` from the reviewed bundle. |
| `atc_install_root` | `/opt/atc`; normalized directory beneath `/opt` or `/srv`. |
| `atc_python_executable` | `/usr/bin/python3`; must be Python 3.10 with venv support. |
| `atc_port` | `8790`, loopback only; integer 1024–65535 excluding datastore ports. |
| `atc_operator_os_user` | Existing non-root local account receiving the protected human client file. |
| `atc_engagement_id`, `atc_engagement_codename` | Explicit first engagement identity; never example operational data. |
| `atc_engagement_status` | `active`, or `planning`, `paused`, `closed`. |
| `atc_operator_id`, `atc_operator_name` | Explicit first human TeamMember identity. |

The controller verifies the complete outer digest, safe archive members, exact
internal checksum coverage, release/source/migration/PostgreSQL identities and
required offline wheelhouses before target writes. The app repeats its own
bundle/Git-source and host preflight before managed installation changes. The
role uses fresh private staging, verifies the delivered digest, and removes only
that invocation's staging afterward. No SCM credentials reach Homebase.

## Convergence and safety

An unchanged installation uses read-only checks and skips the installer: no
venv rebuild, PostgreSQL restart or token creation. A missing owned command or
failed local readiness requests the app's same-release repair. Repair is allowed
only when its upstream preflight accepts the retained installation. Corruption
that prevents that preflight requires the app's documented operator procedure.

The role refuses changed release/artifact, engagement/operator settings, listener
or datastore configuration, local source patches, unsafe state, incomplete
installation phases, and any restore/upgrade marker. It preserves databases,
artifacts, encryption keys, client credentials and recovery journals. It neither
resets a database nor resumes, rolls back or upgrades a deployment automatically.
An existing same-release app installation without the role receipt undergoes
same-release repair before the role records its reviewed artifact identity.

Graph and inference stay unconfigured. The app release contains dormant graph
runtime material; packaging that material is not graph acceptance. Existing
`topo.env` or `inference.env` makes this initial adapter refuse convergence rather
than start optional workers during repair. Manage those deployments explicitly
through the application; their files are preserved.

Local readiness proves the API's service account/PID owns exactly the selected
loopback listener, `/healthz` reports the exact release, installed source is clean,
and the labelled PostgreSQL container runs the pinned image with only
`127.0.0.1:15432` exposed. This does not prove application workflows, graph,
inference access, or separate agent readiness. No public ingress, DNS or
certificate is created.

The app installer creates the first human's mode-0600 client file without
printing its token. Operator Brief setup and separate protected agent identities
remain manual application steps. Never give an agent the human client file.
Installer output is suppressed by Ansible; inspect local service journals and
follow ATC's installation/recovery guide for failures. Installer output is
retained (bounded and potentially sensitive) in root-only
`/var/cache/atc/last-install-result.json` after disposable staging is removed;
inspect it locally with sudo, never paste it into UI logs or tickets. Do not
delete journals or rerun against a different artifact to bypass a failure.

Removal and cross-release upgrades are manual. Deselecting this capability does
not delete its services or retained records. Whole disposable-engagement teardown
is a separate Barragan operation.

## Verification

From the RTI repository root:

```sh
python3 -m unittest discover -s ansible/roles/atc/tests -p 'test_*.py' -v
ANSIBLE_ROLES_PATH="$PWD/ansible/roles" ansible-playbook -i localhost, \
  ansible/roles/atc/tests/syntax.yml --syntax-check
```

Broader native lifecycle qualification can separately cover unchanged reapply,
missing-command repair, retained data/key/client hashes, listener isolation and
coexistence. Do not describe these as passed based only on source packaging or
a successful fresh installation.

Optional local Ansible safety gates (uses a harmless Docker-role fixture):

```sh
ROLE_GATE_ANSIBLE="$(command -v ansible-playbook)" python3 -m unittest discover \
  -s ansible/roles/atc/tests -p 'test_prerequisite_gates.py' -v
```

These prove invalid OS/artifacts cannot select the dependency role and existing,
stopped, old, incomplete or retained-with-missing engines cannot trigger an
upgrade/recreation. They do not install Docker or qualify native lifecycle.
