# Inference Proxy on Homebase

Implementation and qualification are in progress in
[WI-0461](../../work-items/WI-0461-inference-proxy-capability.md). This is the
installation contract, not a claim that the capability is released.

## Operator action

Select **Inference Proxy** in Homebase capabilities. Enter the OCI inference
region, model compartment OCID and local port (default `8787`). Save the
capability changes, then Apply them to running infrastructure. The model
compartment and inference region can differ from Homebase's compute placement.
Use the authorized model compartment from your working inference deployment.
The role defaults to instance-principal authentication and `us-chicago-1`;
the model compartment stays explicit. Each new Homebase needs its own matching
OCI identity permissions, even when it uses the same model compartment.

Barragan shows the required instance-principal membership and compartment-scoped
OCI policies. An OCI administrator configures them externally. Barragan never
creates or changes IAM policies or dynamic groups. Installing the service does
not require the operator to claim that those permissions are already working.

## Controller prerequisite

The administrator supplies a clean Git checkout of the reviewed application
revision and sets `BARRAGAN_INFERENCE_PROXY_SOURCE_ROOT` to its absolute path
on the API service. Its HEAD must equal `SOURCE_REVISION` in
`backend/app/services/inference_proxy_capability.py`. The configured RTI
template root must also contain `ansible/roles/inference_proxy`. Changing these
paths follows the normal committed-revision deployment and idle-worker restart
procedure; it is not an engagement setting.

The RTI role owns installation and service convergence. It consumes the pinned
application package and systemd units directly; it does not invoke the manual
shell installer or configurer. Application source remains independently versioned.

Save archives committed application files on the controller and binds the
revision and checksum to the capability lock. No source checkout credentials
are sent to Homebase. An absent, dirty or mismatched checkout stops Save with
a preparation error; fix the controller source rather than granting Homebase
access to SCM. Current qualification revisions and release limits are in
[WI-0461](../../work-items/WI-0461-inference-proxy-capability.md).

## Ordered installation and proof

1. Validate Homebase placement and the explicit configuration. Bind the saved
   configuration and reviewed application revision/archive digest to the
   capability lock. Missing source material is a preparation error, before a
   host mutation. SCM credentials stay on the controller.
2. Use the existing owned-core identity checks and capability job to apply the
   upstream role. Install the loopback service, protected configuration and
   service account. Create the pepper once; preserve keys, SQLite usage data
   and other operator configuration on reapply and repair.
3. Record installation and local service checks in the job. Process/database
   health does not prove OCI access. Missing upstream authorization must leave
   an explicit access warning rather than an infrastructure rollback or a false
   inference-success label. The current pinned application passed native Ubuntu
   24.04 installation/file/local-service checks without OCI access. Same-release
   reapply and missing-command repair were demonstrated on a predecessor pin;
   they were not repeated on the current pin.
   Issued-key preservation, nonempty usage history, authorized inference and
   upstream acceptance remain separate outstanding gates.
4. In the Inference Proxy configuration, use **Check service and OCI
   discovery**. It checks the saved configuration on the current Homebase,
   verifies the service owns its loopback listener and shows the check time,
   discovery result and last successful catalog refresh. Its verified Homebase
   instance ID fills the single-instance membership example. Before that check,
   the example remains a labelled placeholder; an OCI administrator can obtain
   the instance ID directly from OCI.
5. After externally configuring IAM, allow time for propagation and background
   discovery, then check again. A catalog being available still does not prove
   inference works. To force a model catalog refresh, use the Homebase admin path:
   `/opt/inference-proxy/venv/bin/inference-proxy-admin model refresh`.
   Verify authenticated model discovery and an approved bounded inference
   request separately. Generate scoped agent credentials on Homebase and keep
   them out of shared logs. Inference probes can incur charges.

The UI status check issues no keys, IAM writes or inference calls. Missing or
untrusted Homebase evidence blocks it. Saving different inputs, deselecting the
role, replacing the core or tearing it down invalidates earlier results. The
check preserves unsaved form edits; save and apply those edits before checking
them. A timeout or malformed response is an unsuccessful check, not evidence
that OCI policies are wrong. OCI's not-authorized-or-not-found response also
requires reviewing the selected region and model compartment.

For details on Homebase, run
`sudo /opt/inference-proxy/venv/bin/inference-proxy-admin status`.
It reads local readiness and the latest discovery result, including a sanitized
failure and HTTP status when available. It does not refresh models or run
inference. `doctor` checks local configuration, pepper and database only.
Service warnings are available with `sudo journalctl -u inference-proxy`.
The installed CLI diagnostics and UI status check passed native local-service
qualification; discovery remained unavailable.

Native Ubuntu 24.04 qualification verified this status workflow against the
installed service: current instance identity, local readiness and unavailable
OCI discovery were shown separately. Authorized inference remains unqualified.
Ubuntu 22.04 and cross-release upgrades remain unqualified; the repair evidence
covers reinstalling the same pinned source revision.

## Failure, reapply and cleanup

Configuration or source errors stop preparation without deploying. Host failures
remain visible in the existing capability job; retry preserves identity and
data. Reapply must converge without an unconditional dependency upgrade or
restart. A provider error is not automatically an IAM error. Existing listener,
authentication, storage, region or model-compartment differences require a
separately reviewed migration; ordinary reapply must refuse them before writes.
Do not change a saved port expecting the role to move an existing service.

Deselecting this role does not uninstall the service. Removal is manual until a
preserve/disable workflow is implemented and tested. Engagement teardown destroys
the owned Homebase normally; no separate uninstall is needed before destroying
that host. Never purge retained data as part of repair. No public ingress, DNS,
certificate, agent key or IAM write is implicit in capability selection.

## Review and acceptance

Use one optional Homebase role and the existing Save/Apply workflow. Avoid a
general IAM editor or another deployment coordinator. The operator narrowed the current acceptance to installation/files/local health;
IAM setup and LLM functional tests are explicitly deferred. This does not turn
unverified inference or state-preservation paths into passes. Broader release
proof remains: catalog
and rendering tests, exact source/configuration binding, Ubuntu first install,
unchanged reapply and repair with retained data, honest no-access behavior,
authorized discovery/inference, UI screenshots and exact disposable cleanup.
