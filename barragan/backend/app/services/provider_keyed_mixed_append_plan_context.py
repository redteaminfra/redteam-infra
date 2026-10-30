# Copyright (c) 2026, Oracle and/or its affiliates.
"""Server-owned inputs for a reviewed mixed 4-to-6 append.

The pre-reservation reader accepts only two edge choices from a published,
lease-free generation. After reservation, the plan reader reauthenticates the published
generation and compares every stored, enriched request field with those same
retained inputs. Neither reader plans or writes provider resources.
"""

from __future__ import annotations

from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows
from app.services.provider_keyed_mixed_append_availability import (
    MixedAppendAvailabilityAttention, require_mixed_append_digitalocean_availability,
    require_no_independent_mixed_append_bindings,
)

from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
from typing import Mapping

from app.services.provider_keyed_initial_plan_gate import DigitalOceanInitialFirewallIntent
from app.services.provider_keyed_mixed_append_intent import (
    compile_mixed_digitalocean_on_linode_append_intent,
)
from app.services.provider_keyed_mixed_append_linode_intent import (
    compile_mixed_linode_on_digitalocean_append_intent,
)
from app.services.provider_keyed_mixed_append_live_bindings import collect_mixed_append_live_bindings
from app.services.provider_keyed_mixed_append_pair_parent import (
    ACTION, _digest, _parent_id,
)
from app.services.provider_keyed_mixed_append_published_source import collect_published_mixed_append_source
from app.services.provider_keyed_mixed_initial_apply_child import (
    _child_id, _prior_workspace, recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_host_binding import (
    _binding_child_id, recognize_mixed_initial_host_binding,
)
from app.services.provider_keyed_mixed_initial_plan_parent import (
    _parent_id as _initial_parent_id, validate_mixed_initial_apply_seal,
)
from app.services.provider_keyed_mixed_append_pair_plan_worker import _read
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_sketch import read_provider_topology, ProviderKeyedWorkspace
from app.services.sketch_ssh_keys import retrieve_sketch_ssh_key
from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository
from app.storage.sketch_ssh_key_repository import SqlAlchemySketchSshKeyRepository


_PROVIDERS = frozenset({"digitalocean", "linode"})
_CHOICES = {"digitalocean": frozenset({"selectedChainId", "edgeRegion", "edgeSize"}),
            "linode": frozenset({"selectedChainId", "edgeRegion", "edgeType"})}
_RECEIPT = {"digitalocean": ".barragan-digitalocean-plan-receipt.json",
            "linode": ".barragan-linode-plan-receipt.json"}
_PATH_KEYS = frozenset({"ssh_pub_key_path", "ssh_priv_key_path", "ssh_config_path"})


class MixedAppendPlanContextAttention(ValueError):
    """The selected source or retained input requires read-only reconciliation."""


class MixedAppendAvailabilityContextAttention(MixedAppendPlanContextAttention):
    """A safe purchase-availability message for the fresh Review boundary."""


@dataclass(frozen=True)
class MixedAppendPlanChoices:
    reviewed_request: dict[str, dict[str, str]]
    provider_order: tuple[str, str]
    chain_order: tuple[str, str]
    core_plan_id: str


@dataclass(frozen=True)
class MixedAppendPlanContext:
    source: object
    binding_manifest: dict
    provider_states: dict[str, bytes]
    workspaces: dict[str, ProviderKeyedWorkspace]
    original_topologies: dict[str, dict]
    original_regional_high_water: dict[str, int]
    retained_varfiles: dict[str, dict]
    additions: dict[str, dict[str, str]]
    digitalocean_firewall: DigitalOceanInitialFirewallIntent
    reviewed_provider_order: tuple[str, str]
    reviewed_chain_order: tuple[str, str]
    lease_owner: str
    admin_public_key: str
    admin_private_key: str

    def producer_kwargs(self) -> dict:
        """Exact private producer arguments; secrets remain server-side."""
        return dict(source=self.source, binding_manifest=self.binding_manifest,
                    provider_states=self.provider_states, workspaces=self.workspaces,
                    original_topologies=self.original_topologies,
                    original_regional_high_water=self.original_regional_high_water,
                    retained_varfiles=self.retained_varfiles, additions=self.additions,
                    digitalocean_firewall=self.digitalocean_firewall,
                    reviewed_provider_order=self.reviewed_provider_order,
                    reviewed_chain_order=self.reviewed_chain_order,
                    lease_owner=self.lease_owner,
                    admin_public_key=self.admin_public_key,
                    admin_private_key=self.admin_private_key)

    def approval_kwargs(self) -> dict:
        """Rebuild the two reviewed intents without planning or writing state."""
        states = {row.provider: row for row in self.source.provider_states}
        from app.services.provider_keyed_mixed_append_pair_plan_producer import _complete_retained_resource_ids
        resource_ids = _complete_retained_resource_ids(self.provider_states, states)
        state_sha = {provider: states[provider].state_sha256
                     for provider in _PROVIDERS}
        base = dict(published_binding=self.binding_manifest,
                    provider_states=self.provider_states,
                    provider_state_sha256=state_sha,
                    provider_resource_ids=resource_ids)
        digitalocean = compile_mixed_digitalocean_on_linode_append_intent(
            **base, retained_digitalocean_varfile=self.retained_varfiles["digitalocean"],
            **self.additions["digitalocean"])
        linode = compile_mixed_linode_on_digitalocean_append_intent(
            **base, retained_linode_varfile=self.retained_varfiles["linode"],
            admin_public_key=self.admin_public_key, **self.additions["linode"])
        return dict(binding_manifest=self.binding_manifest,
                    digitalocean_intent=digitalocean, linode_intent=linode,
                    workspaces=self.workspaces, provider_states=self.provider_states,
                    reviewed_inputs={"digitalocean": digitalocean.nonsecret_varfile,
                                     "linode": linode.nonsecret_varfile},
                    digitalocean_firewall=self.digitalocean_firewall)


def _json_private(path: Path) -> dict:
    value = json.loads(_read(path))
    if type(value) is not dict:
        raise ValueError("retained JSON input differs")
    return value


def _initial_material(engagement_id: str, core_job_id: str, *, jobs, plans,
                      sketches, keys, lease_lookup, operation: str):
    core = jobs.get(core_job_id)
    parent = jobs.get(_initial_parent_id(core_job_id))
    if (core is None or parent is None or core.input.get("engagementId") != engagement_id
            or parent.target_id != engagement_id):
        raise ValueError("selected core identity differs")
    plan = plans.get(core.input.get("corePlanId"))
    expected_lease = None if operation == "lease_free" else (
        plan.id if plan is not None else "", operation)
    if (plan is None or plan.id != parent.input.get("corePlanId")
            or lease_lookup(engagement_id) != expected_lease):
        raise ValueError("selected core plan or lease differs")
    seal = validate_mixed_initial_apply_seal(parent)
    order = tuple(seal["orderedProviders"])
    ids = tuple(seal["chainIds"])
    if len(order) != 2 or set(order) != _PROVIDERS or len(set(ids)) != 2:
        raise ValueError("original provider order differs")
    binding = jobs.get(_binding_child_id(core_job_id))
    if binding is None:
        raise ValueError("original binding is missing")
    # Binding was reserved at the seven-event host-proof handoff. The eighth
    # event sealed the initial publication after that immutable child existed.
    if len(parent.events) != 8:
        raise ValueError("completed mixed parent journal differs")
    historical = replace(parent, events=parent.events[:7])
    manifest = recognize_mixed_initial_host_binding(binding, historical)
    if manifest["chainIds"] != list(ids) or manifest["orderedProviders"] != list(order):
        raise ValueError("original binding order differs")
    chains = {row.chain_id: row for row in reviewed_mixed_chain_rows(
        sketches.list_for_engagement(engagement_id), ids, engagement_id)}
    if (set(chains) != set(ids) or any(chains[chain_id].status != "deployed"
                                    or len(chains[chain_id].nodes) != 2
                                    for chain_id in ids)):
        raise ValueError("published four-host chains differ")
    workspaces, topologies, retained = {}, {}, {}
    for index, provider in enumerate(order):
        child = jobs.get(_child_id(core_job_id, provider))
        if child is None:
            raise ValueError("initial Apply child is missing")
        terminal = recognize_mixed_initial_apply_terminal(child, historical, provider)
        workspace = _prior_workspace(parent, provider, terminal)
        root = workspace.path
        receipt_bytes = _read(root / _RECEIPT[provider])
        receipt = json.loads(receipt_bytes)
        if (type(receipt) is not dict or receipt.get("schema") != f"mixed-{provider}-saved-plan-v1"
                or receipt.get("engagementId") != engagement_id
                or receipt.get("coreJobId") != core_job_id
                or receipt.get("corePlanId") != plan.id
                or receipt.get("connectionId") != workspace.provider_connection_id
                or _digest(receipt) != parent.events[index + 2].data.get("receiptSha256")):
            raise ValueError("original saved plan receipt differs")
        inputs_path = root.parents[1] / ".plan-material" / provider / "inputs.json"
        inputs_bytes = _read(inputs_path)
        if hashlib.sha256(inputs_bytes).hexdigest() != receipt.get("inputSha256"):
            raise ValueError("original saved plan input differs")
        inputs = json.loads(inputs_bytes)
        policy = seal["reviewedPolicy"][provider]
        varfile = policy["nonsecret_varfile"]
        if (type(inputs) is not dict or type(varfile) is not dict
                or {key: value for key, value in inputs.items() if key not in _PATH_KEYS} != varfile
                or set(inputs) != set(varfile) | _PATH_KEYS):
            raise ValueError("original reviewed Terraform variables differ")
        original_topology = policy["topology"]
        if (type(original_topology) is not dict
                or original_topology.get("schema") != "provider-keyed-v2"):
            raise ValueError("original reviewed topology differs")
        current_topology = read_provider_topology(workspace)
        if operation == "lease_free" and current_topology != original_topology:
            raise ValueError("original provider topology drifted before reservation")
        # A previous planning attempt may have atomically reserved the two
        # proposed topologies. The producer rechecks that exact proposal.
        workspaces[provider] = workspace
        topologies[provider] = original_topology
        # Preserve the original hash-bound server paths as well as policy
        # variables: the append producer stages its keys at those exact paths.
        retained[provider] = inputs
    schema_root = workspaces[order[0]].path.parents[1]
    if schema_root != workspaces[order[1]].path.parents[1]:
        raise ValueError("provider workspaces are not joined")
    # The ordinal ledger is nonsecret workspace metadata. Collaborator access
    # deliberately makes it group-readable; retain the stable regular-file
    # read and exact topology comparison without imposing private-key modes.
    current_ledger = json.loads(_read(schema_root / "regional-ordinals.json", private=False))
    if type(current_ledger) is not dict:
        raise ValueError("engagement-wide ordinal ledger shape differs")
    expected = {}
    for provider in order:
        for region, ordinal in topologies[provider]["regional_high_water"].items():
            expected[region] = max(expected.get(region, 0), ordinal)
    if operation == "lease_free" and current_ledger != expected:
        raise ValueError("engagement-wide ordinal ledger differs")
    ledger = expected
    material = retrieve_sketch_ssh_key(engagement_id, keys)
    if (material is None or not material.private_key or not material.public_key
            or any(seal["reviewedPolicy"][p]["admin_public_key"] != material.public_key
                   for p in order)
            or any(receipt.get("adminPublicKeySha256") != hashlib.sha256(
                material.public_key.encode()).hexdigest() for receipt in (
                _json_private(workspaces[p].path / _RECEIPT[p]) for p in order))):
        raise ValueError("durable Sketch administration key differs")
    return (core, plan, parent, seal, manifest, chains, workspaces, topologies,
            ledger, retained, material)


def _derive(choices: Mapping[str, Mapping[str, str]], *, plan, seal,
            retained) -> MixedAppendPlanChoices:
    if (type(choices) is not dict or set(choices) != _PROVIDERS
            or any(type(choices[p]) is not dict or set(choices[p]) != _CHOICES[p]
                   or any(type(value) is not str or not value
                          for value in choices[p].values()) for p in _PROVIDERS)):
        raise ValueError("append choices are not minimal")
    order = tuple(seal["orderedProviders"])
    by_provider = {p: chain_id for p, chain_id in zip(order, seal["chainIds"], strict=True)}
    request = {}
    for provider in _PROVIDERS:
        choice = choices[provider]
        foreign = "linode" if provider == "digitalocean" else "digitalocean"
        if choice["selectedChainId"] != by_provider[foreign]:
            raise ValueError("selected opposite-provider chain differs")
        varfile = retained[provider]
        image = varfile["docean_image" if provider == "digitalocean" else "linode_image"]
        size = varfile["edge_size" if provider == "digitalocean" else "edge_type"]
        tag = varfile["firewall_selector_tag" if provider == "digitalocean" else "engagement_name"]
        if (choice["edgeSize" if provider == "digitalocean" else "edgeType"] != size
                or not isinstance(image, str) or not image
                or not isinstance(tag, str) or not tag):
            raise ValueError("edge choice differs from retained generation")
        request[provider] = {
            **choice, "edgeImage": image,
            "selectorTag" if provider == "digitalocean" else "engagementTag": tag,
        }
    return MixedAppendPlanChoices(request, order,
                                  tuple(request[p]["selectedChainId"] for p in order),
                                  plan.id)


def derive_mixed_append_review_request(
    engagement_id: str, core_job_id: str, choices: dict, *, job_repository=None,
    plan_repository=None, sketch_repository=None, ssh_key_repository=None,
    lease_lookup=None, credential_repository=None, catalog_transport=None, domain_repository=None,
) -> MixedAppendPlanChoices:
    """Derive enriched server request before reserving the append lease."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    keys = ssh_key_repository or SqlAlchemySketchSshKeyRepository()
    lookup = lease_lookup or _db_lease_lookup
    try:
        (_, plan, _, seal, _, chains, _, _, _, retained, _) = _initial_material(
            engagement_id, core_job_id, jobs=jobs, plans=plans, sketches=sketches,
            keys=keys, lease_lookup=lookup, operation="lease_free")
        derived = _derive(choices, plan=plan, seal=seal, retained=retained)
        require_no_independent_mixed_append_bindings(engagement_id, jobs=jobs,
            domain_repository=domain_repository)
        selected = derived.reviewed_request["digitalocean"]
        require_mixed_append_digitalocean_availability(
            seal["reviewedPolicy"]["digitalocean"], selected["edgeRegion"], selected["edgeSize"],
            credential_repository=credential_repository, catalog_transport=catalog_transport)
        return derived
    except MixedAppendAvailabilityAttention as exc:
        raise MixedAppendAvailabilityContextAttention(str(exc)) from None
    except Exception:
        raise MixedAppendPlanContextAttention(
            "mixed append request needs exact original-generation review") from None


def collect_mixed_append_pair_plan_context(
    parent_id: str, *, job_repository=None, plan_repository=None,
    sketch_repository=None, ssh_key_repository=None, lease_lookup=None,
    published_reader=None,
) -> MixedAppendPlanContext:
    """Reopen server authority after reservation, before either Terraform plan."""
    jobs = job_repository or SqlAlchemyJobRepository()
    plans = plan_repository or SqlAlchemyDeploymentPlanRepository()
    sketches = sketch_repository or SqlAlchemySketchChainRepository()
    keys = ssh_key_repository or SqlAlchemySketchSshKeyRepository()
    lookup = lease_lookup or _db_lease_lookup
    reader = published_reader or (lambda engagement, core: collect_published_mixed_append_source(
        engagement, core, binding_inventory=lambda: collect_mixed_append_live_bindings(engagement),
        job_repository=jobs, plan_repository=plans, sketch_repository=sketches,
        lease_lookup=lookup))
    try:
        parent = jobs.get(parent_id)
        if (parent is None or parent.id != _parent_id(parent.input["coreJobId"])
                or parent.action != ACTION or parent.input.get("phase") != "planning"
                or parent.input.get("schema") != "mixed-append-pair-parent-v1"
                or parent.target_id != parent.input.get("engagementId")):
            raise ValueError("selected append parent differs")
        engagement_id, core_job_id = parent.target_id, parent.input["coreJobId"]
        (core, plan, _, seal, manifest, _, workspaces, topologies,
         ledger, retained, material) = _initial_material(
            engagement_id, core_job_id, jobs=jobs, plans=plans, sketches=sketches,
            keys=keys, lease_lookup=lookup, operation="provider_keyed_mixed_append")
        choices = {p: {k: parent.input["reviewRequest"][p][k] for k in _CHOICES[p]}
                   for p in _PROVIDERS}
        derived = _derive(choices, plan=plan, seal=seal, retained=retained)
        if (parent.input["reviewRequest"] != derived.reviewed_request
                or tuple(parent.input["providerOrder"]) != derived.provider_order
                or tuple(parent.input["chainOrder"]) != derived.chain_order
                or parent.input["corePlanId"] != plan.id
                or parent.input["requestSha256"] != _digest({
                    "request": derived.reviewed_request,
                    "providerOrder": derived.provider_order,
                    "chainOrder": derived.chain_order})):
            raise ValueError("stored append request differs from server authority")
        published = reader(engagement_id, core_job_id)
        source = published.source
        if (source.engagement_id != engagement_id or source.core_job_id != core_job_id
                or source.core_plan_id != plan.id
                or source.binding_manifest_sha256 != _digest(manifest)
                or dict(published.workspaces) != {p: workspaces[p].path for p in _PROVIDERS}):
            raise ValueError("published generation differs")
        states = {p: _read(workspaces[p].state_path, private=False) for p in _PROVIDERS}
        if any(hashlib.sha256(states[p]).hexdigest() != next(
                row.state_sha256 for row in source.provider_states if row.provider == p)
               for p in _PROVIDERS):
            raise ValueError("retained Terraform state differs from publication")
        do = retained["digitalocean"]
        selected_linode = next(row for row in manifest["nodes"]
                               if row["chainId"] == choices["digitalocean"]["selectedChainId"]
                               and row["provider"] == "linode" and row["role"] == "middle")
        firewall = DigitalOceanInitialFirewallIntent(
            f'{do["engagement_name"]}-firewall', do["firewall_selector_tag"],
            tuple(do["allowed_tcp_ports"][1:]), tuple(do["allowed_udp_ports"]),
            (do["trusted_ssh_cidrs"][0], selected_linode["publicIp"] + "/32"))
        # All fields below are sourced from the persisted publication, original
        # saved inputs/ledger, or encrypted durable key, never from the UI.
        return MixedAppendPlanContext(
            source, manifest, states, workspaces, topologies, ledger, retained,
            {p: {"selected_chain_id": choices[p]["selectedChainId"],
                 "edge_region": choices[p]["edgeRegion"],
                 "edge_size" if p == "digitalocean" else "edge_type":
                     choices[p]["edgeSize" if p == "digitalocean" else "edgeType"],
                 "edge_image": derived.reviewed_request[p]["edgeImage"],
                 "selector_tag" if p == "digitalocean" else "engagement_tag":
                     derived.reviewed_request[p]["selectorTag" if p == "digitalocean" else "engagementTag"]}
             for p in _PROVIDERS},
            firewall, derived.provider_order, derived.chain_order, plan.id,
            material.public_key, material.private_key)
    except Exception:
        raise MixedAppendPlanContextAttention(
            "mixed append plan context needs exact read-only reconciliation") from None
