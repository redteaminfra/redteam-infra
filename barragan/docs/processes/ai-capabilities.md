# Install AI and evidence capabilities

Status: Inference Proxy has a native installation receipt; C2 Observer has a
native CLI/dependency and synthetic-episode validation receipt. LootTool native
image import, local health, synthetic ingestion/search and citation resolution
and same-release preservation passed. ATC 0.6.1 fresh installation and local
readiness passed through Barragan. Broader functional/preservation testing was
deferred by the operator; it is not a source-publication prerequisite. The release is at exact source
`e9cda6c7ced6c828b619c30b68e24459708a3e16`; source-owner release acceptance does
not replace Barragan role acceptance. Historical 0.6.0 artifacts and receipts
retain their original identities. Saving prepares the new exact artifact;
existing installations are not silently upgraded. The roles and Barragan Save/Apply wiring
have passed code review; that alone does not qualify deployment.

Operator selects a Homebase capability, supplies required configuration, saves
and applies. Barragan validates placement and typed inputs, pins the application
artifact and RTI role, imports only missing retained roles, and runs the existing
capability job. The role validates platform, artifact and retained boundaries
before installation, preserves private records/keys, and checks local readiness.
ATC and LootTool install the upstream Docker runtime on Homebase only when it is
genuinely absent, after role preflight. Existing or partial installations are
preserved or refused; the roles do not upgrade or restart them automatically.
This prerequisite path has passed code and isolated Ansible review. The ATC
qualification installed Docker on a host where it was genuinely absent.
No IAM modification, public ingress, inference requests, C2 collection or finding
publication occurs merely from installation. External readiness remains separate. LootTool baseline starts search and private
Elasticsearch without mounting or ingesting source loot. Explicit ingestion needs
its own read-only source access check; installing search does not grant that access.

Prepared engagement workspaces pin their role source. Updating Barragan or its
configured RTI checkout does not refresh existing role directories. Save imports
missing roles only. A correction to an already-retained role needs a reviewed
source migration; do not patch the host or assume Retry picks up a new checkout.

On failure retain the exact job, artifact identity and state; repair the same
release without resetting records. Do not start another infrastructure deployment
while a worker is live. Application upgrades and destructive removal require
their documented lifecycle contract.

Qualification retains disposable infrastructure until all role tests finish.
Current platform support requires an Ubuntu24 Homebase for Inference Proxy,
C2 Observer and LootTool, and a separate Ubuntu22/Python3.10 Homebase for ATC.
Do not bypass platform admission or claim four-role coexistence from this split.
Record committed revisions, meaningful UI screenshots, local service/CLI proof,
unchanged reapply and state preservation. Tear down only after all role checks
finish. Install proof does not certify LLM, ATC pairing or live C2 collection.

KISS: applications stay in their own repositories; RTI installs pinned artifacts;
Barragan uses its existing Save/Apply/jobs workflow. No second installer or
application source copies in role directories. See
[the contributor contract](../../spec/ansible-role-adoption.md).
