# C2 Observer tooling

Installs the application-owned CLI on Homebase. It creates no systemd unit,
scheduler, listener, C2 credentials, inference requests or ATC submissions.
Collection and evidence attachment are separate operator workflows. CLI health
proves process imports only, not Mythic or ATC connectivity.

Required controller inputs: `c2_observer_source_archive` (flat Git archive),
`c2_observer_source_sha256`, full40-character `c2_observer_source_revision`,
`c2_observer_dependency_lock` and its `c2_observer_dependency_sha256`. The lock
must contain the complete application/build closure with pip hashes and platform
wheels (source dependencies are refused to prevent unpinned isolated builds); no mutable
source checkout, credentials or application history is delivered. Source owner
must review the selected artifact and lock before deployment. Ubuntu22.04/24.04
with Python>=3.11 is the intended boundary; Ubuntu22 requires a separately
provided supported Python, not an automatic system-Python replacement. Neither
platform is natively qualified by this role yet.

Install path `/opt/c2-observer`, isolated `venv`, root-owned source and receipt;
private state `/var/lib/c2-observer` belongs to `c2-observer`. Reapply repairs the
same source/lock while preserving all state. Repair recreates only the guarded
stateless Python virtual environment; private durable state is never cleared. Changing source or dependencies is
an explicit upgrade, refused here. Existing unmanaged installs and symlinked
paths are refused before writes. Never delete receipts, WAL/SHM, outbox or keys
as a repair. Removal and upgrade remain manual. Do not supply production state
to a disposable test.

Use `/opt/c2-observer/venv/bin/c2-observer health` for a local import check.
Use the application's operator guide for protected credentials and explicitly
approved one-shot collection. The role never runs those commands automatically.
Tests: `python3 -m unittest discover -s ansible/roles/c2_observer/tests` and
`ANSIBLE_ROLES_PATH=ansible/roles ansible-playbook -i localhost, ansible/roles/c2_observer/tests/syntax.yml --syntax-check`.
