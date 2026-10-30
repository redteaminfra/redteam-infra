# LootTool V2 baseline installation

Installs the pinned LootTool Compose search baseline on a dedicated Ubuntu
24.04 amd64 Homebase: certificate setup, private Elasticsearch, service-user
setup and loopback search API. Installation, explicit fixture ingestion, search, citations
and same-release data preservation have been verified on Ubuntu 24.04 with Docker 29.
It does not ingest loot, start the optional answer API/Explorer worker, schedule
jobs, publish to ATC, issue inference tokens or modify IAM. Port 8082 is reserved
in the runtime contract but no answer service is activated.

## Inputs and prerequisites

| Variable | Required value |
| --- | --- |
| `loottool_v2_source_archive` | Absolute controller path to flat `git archive --format=tar.gz COMMIT` source |
| `loottool_v2_source_sha256` | Reviewed source artifact SHA256, 64 lowercase hex |
| `loottool_v2_source_revision` | Exact source commit, 40 lowercase hex |
| `loottool_v2_app_image` | Registry `repository@sha256:MANIFEST`, or full local `sha256:ID`; linux/amd64 with OCI full-revision label |
| `loottool_v2_app_archive` / `loottool_v2_app_archive_sha256` | Local-image mode: absolute controller Docker-save archive path and reviewed SHA256 |
| `loottool_v2_app_config_digest` | Local-image mode: independently reviewed `sha256:CONFIG` identity; do not equate it with an index/manifest ID |
| `loottool_v2_elasticsearch_image` | Reviewed Elasticsearch registry digest reference, linux/amd64 |
| `loottool_v2_python_image` | Reviewed Python base registry digest reference recorded by the application's preflight; the role does not build images |
| `loottool_v2_evidence_scope` | Explicit retrieval boundary; default `shared-loot`, never inferred source-engagement provenance |
| `loottool_v2_source_root` | Existing source directory, default `/engagement/loot` |
| `loottool_v2_api_port` / `loottool_v2_answer_port` | Distinct unprivileged loopback ports; defaults `8080` / `8082` |

At least 10GiB RAM, 50GiB free on `/var/lib`, and
`vm.max_map_count >=1048576` must already be available. OS, resources, paths,
retained identity and exact source/image artifacts are checked before dependency
changes. A fresh host with no Docker/containerd executable, socket, package,
service unit or state/configuration footprint installs Docker through RTI's
existing `docker` role. An existing client always skips installation: its daemon
must already run Docker >=24 and Compose >=2.20. Stopped, old or partial engines,
or retained LootTool with missing Docker, require operator reconciliation; this
role never upgrades or starts them. It does not change shared kernel settings.
The source directory must exist, but baseline installation does not read its
contents or require API UID10001 access. Standard root:`redteam` mode2770 loot
remains unchanged. Explicit ingestion is a separate operator workflow: arrange
reviewed read/traverse permissions for that execution identity and use the
upstream read-only `/loot` mount. The role adds no source mount or supplementary
group to the baseline API and never changes original loot permissions/content.

The application remains in its own repository. Supply reviewed distribution
artifacts; the role does not establish licensing. Registry mode requires real
RepoDigests. Local-image mode requires source contract `59a4c468` or an accepted
successor: archive bytes, config content, platform, source label and actual
imported immutable ID are checked independently. The local index/manifest must
lead to the reviewed config; a read-only daemon export must reproduce that
exact config digest. Compose binds the supplied full
local ID, never an imported mutable tag. Different Docker stores can expose
config or index/manifest IDs: supply the reviewed identity actually available on
the target daemon. A mismatch fails before service activation; the role will not
fabricate a RepoDigest or silently repin it. The reviewed local archive passed
native import; other artifacts/stores still need qualification. Run with root
privileges (`become: true`).

## Operator commands

Run on Homebase. The role installs no host `loottool` command. Define this
session-only helper using the installed release; keep `runtime.env` root-private
and do not copy its credentials into your shell:

```sh
release=/opt/loottool-v2/releases/59a4c4682393e1a542dd61493284b2b2a5cdd79f
ltcompose() {
  sudo docker compose --project-name loottool-v2 --project-directory "$release" \
    --file "$release/compose.yaml" --env-file /etc/loottool-v2/runtime.env "$@"
}
ltcompose run --rm --no-deps cli health
curl --fail --silent --show-error http://127.0.0.1:8080/health
ltcompose run --rm --no-deps cli search --mode exact --limit 10
ltcompose run --rm --no-deps cli coverage --json
```

Search prompts for the query, keeping it out of shell history. Results include
source/line citations; use `search --mode exact --json` to obtain the structured
`artifact_id`, then `ltcompose run --rm --no-deps cli resolve ARTIFACT_ID --json`
with that ID to inspect acquisition/manifest provenance. Resolution does not
verify retained source bytes. Use the configured API port if it differs from
8080. The API stays on loopback; remote access requires your approved SSH path.

A fresh, unindexed service can have healthy `/health` while `/v1/coverage`
returns HTTP 503. Check the configured evidence scope's generations:

```sh
scope=$(sudo python3 -c 'import json; print(json.load(open("/etc/loottool-v2/runtime.json"))["LOOTTOOL_EVIDENCE_SCOPE"])')
ltcompose run --rm --no-deps ingester admin generations --engagement "$scope"
```

An empty generation list means ingestion has not created a corpus. Installation
and reapply never ingest automatically. For an **initial** corpus, first arrange
reviewed read/traverse permissions for the ingester identity and write access to
its manifests directory, then set `source_engagement`, `acquisition` and
`generation` to your explicit provenance IDs and run:

```sh
ltcompose run --rm --no-deps ingester admin run --source-root /loot \
  --engagement "$source_engagement" --acquisition "$acquisition" \
  --evidence-scope "$scope" --generation "$generation" \
  --manifest "/manifests/$acquisition.json"
```

This samples using the application's bounded defaults, indexes, validates and
promotes a generation; inspect `admin run --help` to choose sampling limits.
The source mount is read-only. Existing and newly added source directories/files
are preserved; new files do not appear in search until explicitly ingested.
For later additions, use `admin sample` followed by `admin append` (see each
command's `--help`) with a new acquisition and generation ID, preserving prior
indexed acquisitions. Reusing an acquisition ID with changed contents fails.
Do not use a new initial `admin run` as an additive update.

## Preservation and lifecycle

Source is verified on the controller before target writes, including checksum,
Git archive provenance, bounded safe members and the source's own
`loottool.deployment` preflight. Releases remain under
`/opt/loottool-v2/releases/COMMIT`. Retained release files must still match the
reviewed archive before Compose executes. A pre-extraction check refuses changed
bytes, symlinks, hardlinked files, wrong member types and foreign ownership before repair. Missing
members can be restored. Exact root-owned Git archive modes0664/0775 from an
interrupted extraction may be normalized only within the pinned release to
root:root `u=rwX,go=rX`, preserving executable bits. The strict post-extraction
verifier still refuses writable files; original loot and durable state are
outside this normalization. Images are pulled by digest and
inspected for platform/digest; application revision must match its OCI label.
The original application installer is never invoked.

Root-private `/etc/loottool-v2/runtime.json` and `runtime.env` retain the actual
configuration. The initial pair is published atomically from a private intent
directory; interrupted writes retain the same credentials on retry. Three
independent Elasticsearch credentials are generated once;
reapply preserves them. The role refuses missing credentials, mismatched env,
unmanaged project/state trees, symlink paths and changed source/scope/state/
listener/image identity. **Cross-release upgrades are deliberately unsupported**
until a protected backup/active-job/migration/rollback procedure is qualified.
Same-release reapply can repair stopped/missing containers through Compose;
ordinary reapply does not build images or intentionally restart services.

Separate retained data lives under `/var/lib/loottool-v2/`: `elasticsearch`,
`certs`, `manifests`, `reviews`, `explorer` and `atc-outbox`. Ownership follows
the upstream service UIDs; no recursive chown touches original loot. Existing
credentials, TLS and state are never regenerated or deleted on reapply.

Local `/health` proves search/Elasticsearch readiness, not indexed coverage or
LLM functionality. Actual container labels, healthy service state and published
bindings are checked: search is `127.0.0.1:8080` by default, Elasticsearch has
no host ports, optional services must remain absent. Empty-corpus coverage is a
separate outcome; no synthetic indexed generation is created.

Removal and rollback are manual. Do not run `docker compose down -v`, delete
state, rotate credentials or switch only a release symlink as an assumed
rollback. Preserve the runtime files, image and all data, then follow an
explicitly reviewed lifecycle procedure. This role neither starts nor stops
unrelated operator services.

## Verification

From the RTI repository root:

```sh
python3 -m unittest discover -s ansible/roles/loottool_v2/tests -p 'test_*.py' -v
ANSIBLE_ROLES_PATH="$PWD/ansible/roles" ansible-playbook -i localhost, \
  ansible/roles/loottool_v2/tests/syntax.yml --syntax-check
```

Offline tests cover source tampering/unsafe archives, credential preservation,
identity refusal, dotenv injection, image identity/config graph, interrupted
configuration recovery, release symlink refusal and private baseline bindings.
They do not prove Docker installation. Disposable native acceptance must cover
first install, twice-run idempotence, interrupted-install repair, retained
credentials/TLS/data, resource/port/config conflicts before writes, real image
identity and isolation. Exact search on an approved fixture is a separate
functional gate; optional inference and ATC workflows require separate scope.

Optional local Ansible safety gates (uses a harmless Docker-role fixture):

```sh
ROLE_GATE_ANSIBLE="$(command -v ansible-playbook)" python3 -m unittest discover \
  -s ansible/roles/loottool_v2/tests -p 'test_prerequisite_gates.py' -v
```

These prove invalid OS/artifacts cannot select the dependency role and existing,
stopped, old, incomplete or retained-with-missing engines cannot trigger an
upgrade/recreation. They do not install Docker or qualify native lifecycle.

The opt-in `test_release_modes.py` regression additionally needs GNU tar for
actual Ansible extraction. Its local fixture checks Git0664/0775 normalization,
executable preservation and an unchanged outside-release sentinel. A skipped
GNU-tar fixture is not native extraction proof; run it on isolated Linux before
qualification.
