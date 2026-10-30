# Contributing to Barragan

Copyright (c) 2026, Oracle and/or its affiliates.

Submit changes through the enclosing redteam-infra repository's pull-request
process and follow its contribution/sign-off requirements. Keep core control-plane
changes separate from optional application adapters where practical.

Add `Copyright (c) 2026, Oracle and/or its affiliates.` using the source format's
comment syntax for first-party code. Preserve existing third-party attribution.
JSON, generated dependency locks and captured contract data retain their valid
formats; the adjacent `COPYRIGHT` describes the first-party notice boundary.

Use synthetic fixtures and example accounts. Do not commit credentials, runtime
databases, state, real operator inventories, application release bundles or
private operational evidence. Installation-specific values belong in local
configuration. Provider-root changes affect exact source inventories: update
public source pins together without changing identities of retained workspaces.
