# Isolated OCI CLI for DevTest

The tracked DevTest unit currently names `/var/lib/barragan/.local/bin/oci`,
which is absent on `barragan-app`. The backend virtualenv is shared with
production. Install a separate, root-owned, service-readable OCI CLI runtime
and select it through a **DevTest-only** systemd drop-in. The included
`requirements.lock` was resolved on Ubuntu x86_64 / Python 3.10 and pins OCI
CLI 3.84.0 plus transitive hashes. `install.sh` fails closed until the matching
reviewed wheelhouse is present in a root-owned, non-writable artifact path.

Do not run this installer from an uncommitted or group-writable checkout, or
on a cloud host. Do not alter the production unit, its OCI CLI path, or either
backend virtualenv. First stage a committed named revision into a clean
isolated `barragan-app` worktree under the repository deployment discipline in
`AGENTS.md`, then copy the reviewed installer and preflight scripts into the
root-owned runtime directory as described below. The installer refuses unsafe
script paths before installing anything.

## Prepare the offline artifact

The committed `requirements.lock` is the installation authority. On a trusted
Ubuntu 22.04 x86_64 host with `/usr/bin/python3.10`, use an isolated *builder*
virtualenv to download wheels with `--require-hashes` and
`--only-binary=:all:`. Keep the lock, wheelhouse, `sha256sum` inventory, builder
version, and committed Barragan revision together for review. For a future
deliberate lock regeneration, pin and review the lock generator before
compiling `requirements.in` with `--generate-hashes`. A builder sequence is:

```sh
/usr/bin/python3.10 -m venv /tmp/oci-cli-lock-builder
/tmp/oci-cli-lock-builder/bin/python -m pip download --require-hashes \
  --only-binary=:all: --dest wheelhouse -r requirements.lock
sha256sum wheelhouse/*.whl > wheelhouse.sha256
```

Review the committed lock and checksum inventory before moving either to
`barragan-app`. Reject source distributions, missing transitive hashes,
platform-incompatible wheels, and any unexpected dependency resolution. The
host installer uses `--no-index --require-hashes --only-binary=:all:` and cannot
silently fetch or choose a new package version. Check the wheel inventory
again after transfer.

## Install and select DevTest only

Prepare `/opt/barragan/oci-cli-runtime` and an `artifacts` child as root-owned
`0755` directories. Place the reviewed lock at
`/opt/barragan/oci-cli-runtime/artifacts/requirements.lock` (`0644`) and the
reviewed wheels in an `artifacts/wheelhouse` directory (`0755`, wheels `0644`).
Every ancestor must be root-owned and not group/other writable; the installer
rejects `/tmp`, symlinks, and writable artifact trees. Stage `install.sh` and
`preflight.py` as root-owned `0644` files in a root-owned `0755`
`/opt/barragan/oci-cli-runtime/scripts` directory. Compare each staged SHA-256
with `git show <exact-commit>:ops/oci-cli-runtime/<filename>` from the clean
host checkout before execution. Do not execute either file as root from the
shared checkout. Set `OCI_CLI_WHEELHOUSE` and `OCI_CLI_LOCK_FILE` to the safe
artifact paths and run `bash /opt/barragan/oci-cli-runtime/scripts/install.sh`
as root. It creates
`/opt/barragan/oci-cli-runtime/venv-3.84.0/bin/oci` side by side, then prints
the installed path. It refuses to overwrite an existing version directory.
Check that `barragan` can traverse every parent and execute the binary.

When no DevTest job is running, add a systemd override **only** for
`barragan-api-devtest.service`:

```ini
[Service]
Environment=OCI_CLI_PATH=/opt/barragan/oci-cli-runtime/venv-3.84.0/bin/oci
```

Use `systemctl cat barragan-api-devtest.service` to confirm the effective
override and `systemctl cat barragan-fastapi.service` to confirm production was
not changed. Then reload systemd and restart DevTest through `barragan-admin`
according to `docs/agent-workspace/runtime.md`. Do not restart while a job is
running. Record the exact source commit, lock SHA-256, wheelhouse inventory,
runtime path, and service override in WI-0414 before any live E2E mutation.

## Read-only service-user compatibility check

Supply one known **live Barragan-owned** resource ID and a different known
**already retired Barragan-owned** resource ID in `barragan-testing`. Do not
invent an OCID or select a name-matched manual resource: a malformed ID or an
IAM denial can masquerade as absence. The script checks the exact CLI version,
all eight unfiltered list families, exact live GET, and the exact retired GET
404 stderr shape expected by the private OCI absence witness. It does not
mutate cloud resources. Run as the service user with a cleared environment:

```sh
sudo -u barragan env -i \
  PATH=/usr/local/bin:/usr/bin:/bin HOME=/nonexistent LANG=C.UTF-8 \
  PYTHONWARNINGS="ignore:The 'strict' parameter is no longer needed on Python 3+:FutureWarning:urllib3.poolmanager" \
  /usr/bin/python3.10 /opt/redteam-infra/barragan/ops/oci-cli-runtime/self-check.py \
  --oci /opt/barragan/oci-cli-runtime/venv-3.84.0/bin/oci \
  --region us-sanjose-1 --compartment-id "$REVIEWED_TEST_COMPARTMENT_OCID" \
  --live-kind vcn --live-id "$REVIEWED_LIVE_VCN_OCID" \
  --retired-kind vcn --retired-id "$REVIEWED_RETIRED_VCN_OCID"
```

The environment values in the example are supplied by the invoking operator;
the command does not read a personal OCI config or token. Any list/Get/404
shape mismatch, command failure, or warning other than that exact OCI CLI
3.84.0 urllib3 warning is a release blocker; retain the
public keyed gate closed and compare captured, redacted CLI output to the
parser before changing it. The self-check is a compatibility probe, not an
ownership or absence authorization.

## Rollback

After all DevTest jobs are terminal, remove only the DevTest OCI CLI override,
reload systemd, and restart DevTest. Confirm its effective `OCI_CLI_PATH`
returns to the tracked value. Retain the versioned runtime and wheel evidence
for audit until no job or investigation needs them; removal is a separate
reviewed host cleanup. Production requires no rollback because it was never
changed.
