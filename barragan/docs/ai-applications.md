# Optional AI application adapters

Copyright (c) 2026, Oracle and/or its affiliates.

This branch adds Barragan configuration, Save/Apply preparation, artifact
selection and optional RTI roles for ATC, LootTool v2, C2 Observer and Inference
Proxy. Applications remain in their own repositories; this publication includes
adapter source only, not application bundles, wheels, image archives, credentials
or runtime data.

Set `BARRAGAN_REDTEAM_INFRA_TEMPLATE_ROOT` to the clean checkout containing
`ansible/roles/{atc,loottool_v2,c2_observer,inference_proxy}`. Keep
`BARRAGAN_PROVIDER_KEYED_TEMPLATE_ROOT` pointed at the separate pinned provider
snapshot. These roots serve different purposes.

## Administrator-prepared artifacts

Prepare each application's native release/image/dependency artifacts on the
controller using its source owner's release process. Supply the exact local path,
source revision, release version, checksum and supporting digest/lock inputs
required by the corresponding role. A source-code archive is not automatically a
native release bundle. Roles validate the supplied artifact; they do not require
this repository to host a public binary URL. Review licenses and redistribution
terms before distributing any third-party dependency bundle independently.

- ATC: selected application version 0.6.1 at
  `e9cda6c7ced6c828b619c30b68e24459708a3e16`. The reviewed native archive has
  SHA256 `92e53c669ddad370157019f6b818416950ae6577e6408d9c08e6350b53560cd0`.
  Ubuntu 22.04 amd64/systemd and Python 3.10 only; Ubuntu 24.04 is unsupported.
  Use a compatible Homebase deployment; the general managed-host image default
  does not override ATC's platform contract. The ordinary core-only install is
  supported; graph/Topo and inference are optional upstream workflows and remain
  unconfigured by this baseline. Fresh-install compatibility is separate from
  upgrades or retained-instance migration.
- LootTool v2: supply the reviewed image/archive and release identity required by
  `loottool_v2`. The baseline uses loopback/private search and preserves retained
  release identity. Operator commands use explicit Compose; no host wrapper is
  implied. Answer/Explorer/ATC delivery are optional and outside this baseline.
- C2 Observer: supply the reviewed application source archive and exact Linux
  Python 3.12 offline dependency lock/artifacts required by `c2_observer`. The
  adapter does not imply live collection, scheduler or ATC attachment acceptance.
- Inference Proxy: supply its reviewed application archive and configure the
  intended compartment and provider settings. OCI instance-principal IAM policy
  is an administrator prerequisite; the role does not change IAM. Local service
  readiness is separate from model access or inference functionality.

The role READMEs document their complete inputs and retained-state behavior.
Private application binaries and wheelhouses are deliberately absent. Publishing
these adapters does not assert that a third-party bundle redistribution audit is
complete. No additional infrastructure deployment or functional testing was run
for this source publication.
