#!/usr/bin/env bash
# Copyright (c) 2026, Oracle and/or its affiliates.
# Install an isolated OCI CLI for Barragan DevTest from a reviewed wheelhouse.
set -euo pipefail
export PATH=/usr/bin:/bin

runtime_root=${OCI_CLI_RUNTIME_ROOT:-/opt/barragan/oci-cli-runtime}
wheelhouse=${OCI_CLI_WHEELHOUSE:-}
lock_file=${OCI_CLI_LOCK_FILE:-}
python_bin=/usr/bin/python3.10
version=3.84.0
destination="$runtime_root/venv-$version"

die() { printf 'OCI CLI runtime: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die 'run as root; the runtime must be root-owned and service-readable'
[[ -d $runtime_root && ! -L $runtime_root ]] || die 'runtime root must exist as a real directory'
[[ $(stat -c %u "$runtime_root") == 0 ]] || die 'runtime root must be root-owned'
[[ -n $wheelhouse && -d $wheelhouse && ! -L $wheelhouse ]] || die 'set OCI_CLI_WHEELHOUSE to a reviewed directory of wheels'
[[ -n $lock_file && -f $lock_file && ! -L $lock_file ]] || die 'set OCI_CLI_LOCK_FILE to a reviewed hash-locked requirements file'
[[ -x $python_bin && ! -L $python_bin ]] || die 'Python 3.10 executable is unavailable'
[[ $("$python_bin" -c 'import sys; print(".".join(map(str, sys.version_info[:2])))') == 3.10 ]] || die 'requires Python 3.10'
[[ $0 == /* && -f $0 && ! -L $0 ]] || die 'run a real absolute root-staged installer script'
[[ ! -e $destination && ! -L $destination ]] || die 'versioned destination already exists; refuse replacement'
"$python_bin" -I "$(dirname "$0")/preflight.py" --runtime-root "$runtime_root" \
  --lock "$lock_file" --wheelhouse "$wheelhouse" --installer "$0" || die 'offline artifact preflight failed'

# --require-hashes rejects any dependency that is not exactly pinned with a
# digest; --no-index and --only-binary keep build/network behavior out of the
# host installation. The committed lock is resolved for Ubuntu x86_64 /
# Python 3.10 and must be independently reviewed with the wheelhouse.
# Virtualenv entry points embed their installation path. Build at the final
# versioned path, removing only this newly created directory on any failure.
mkdir -- "$destination" || die 'versioned destination already exists'
trap 'rm -rf -- "$destination"' EXIT
env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C.UTF-8 \
  "$python_bin" -I -m venv "$destination"
env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C.UTF-8 PIP_CONFIG_FILE=/dev/null \
  "$destination/bin/python" -I -m pip install --disable-pip-version-check --no-index \
  --find-links "$wheelhouse" --only-binary=:all: --require-hashes \
  --no-cache-dir -r "$lock_file"
env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C.UTF-8 PIP_CONFIG_FILE=/dev/null \
  "$destination/bin/python" -I -m pip check
[[ $(env -i PATH=/usr/bin:/bin HOME=/nonexistent LANG=C.UTF-8 \
  "$destination/bin/oci" --version) == "$version" ]] || die 'installed OCI CLI version differs'
chown -R root:root "$destination"
chmod -R go-w "$destination"
chmod -R a+rX "$destination"
trap - EXIT
printf 'Installed %s/bin/oci; DevTest service remains unchanged.\n' "$destination"
