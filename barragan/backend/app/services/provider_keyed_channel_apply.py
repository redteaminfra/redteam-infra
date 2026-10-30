# Copyright (c) 2026, Oracle and/or its affiliates.
"""The keyed branch of ordinary inbound Apply, using its existing lease/job.

Converge and prove isolated host policy first, review both provider plans,
then release each exact saved binary once. Existing inbound Ansible still
owns transport, proxy sites and termination hosts.
"""
from __future__ import annotations

from app.services.provider_keyed_runtime_preflight import reviewed_mixed_chain_rows

from dataclasses import asdict, replace
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import shlex
import shutil
import tempfile
from uuid import uuid4

from app.core.command_environment import barragan_subprocess_env
from app.core.runtime import runtime_value
from app.services.core_ssh import active_core_connection_details, core_proxy_identity
from app.services.inbound_mutation_fence import _active_mutation_owner
from app.services.provider_keyed_channel_generation import EVENT, read_channel_generation
from app.services.provider_keyed_channel_provider_proof import require_current_keyed_firewall
from app.services.provider_keyed_gated_runner import run_gated_command, UnreapedGatedCommandError
from app.services.provider_keyed_host_policy import Topology, Middle, Edge
from app.services.provider_keyed_ingress_route_ledger import (
    KeyedRouteIntent, render_keyed_route_projection,
)
from app.services.provider_keyed_ingress_update import (
    KeyedIngressUpdate, plan_keyed_ingress_update, apply_keyed_ingress_update, _paths, _write_private_json,
)
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_mixed_append_pair_host_proof import (
    _probe_cross_provider_edge, _child_id as host_child_id, six_host_known_hosts_path,
)
from app.services.provider_keyed_mixed_append_pair_apply_binding import _staged_append_admin_material
from app.services.provider_keyed_mixed_append_pair_apply_child import _child_id as first_child_id
from app.services.provider_keyed_mixed_append_second_apply_child import _child_id as second_child_id
from app.services.provider_keyed_mixed_append_pair_parent import _parent_id as append_parent_id
from app.services.provider_keyed_mixed_append_pair_plan_worker import _read
from app.services.provider_keyed_mixed_initial_apply_child import (
    _prior_workspace, _child_id, recognize_mixed_initial_apply_terminal,
)
from app.services.provider_keyed_mixed_initial_plan_parent import _parent_id as initial_parent_id
from app.services.provider_keyed_mixed_partial_apply_inventory import (
    _linode, _digitalocean, _credential, _FencedLinodeTransport, _FencedDigitalOceanTransport,
)
from app.services.provider_keyed_mixed_partial_apply_source import _state, _inventory
from app.services.provider_keyed_mixed_published_six_source import recognize_mixed_published_six_source
from app.services.provider_keyed_mixed_published_six_journal import validate_mixed_published_six_journals
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.provider_keyed_sketch import read_provider_topology
from app.services.sketch_bootstrap import SketchBootstrapSpec, render_strict_v2_sketch_identity_ssh_config
from app.services.sketch_bootstrap_apply import _core_hosts, _sketch_nodes
from app.services.sketch_ssh_keys import write_existing_sketch_ssh_key_files
from app.storage.credential_repository import SqlAlchemyCredentialRepository
from app.storage.sketch_chain_repository import SqlAlchemySketchChainRepository


HOST_EVENT = "keyed channel isolated host policy proved"


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def load_keyed_channel_source(engagement_id, jobs, *, sketches=None):
    sketches = sketches or SqlAlchemySketchChainRepository()
    core_id = active_core_connection_details(jobs, engagement_id)[0]
    initial, append = jobs.get(initial_parent_id(core_id)), jobs.get(append_parent_id(core_id))
    if initial is None or append is None:
        raise ValueError("channels require a published mixed append generation")
    order = tuple(append.input["providerOrder"])
    children = {order[0]: jobs.get(first_child_id(append.id)),
                order[1]: jobs.get(second_child_id(append.id))}
    source, _ = recognize_mixed_published_six_source(
        append, host_proof_child=jobs.get(host_child_id(append.id)),
        provider_children=children,
        current_chains={row.chain_id: row for row in reviewed_mixed_chain_rows(
            sketches.list_for_engagement(engagement_id), append.input["chainOrder"], engagement_id)})
    generation = read_channel_generation(source, append, initial, jobs)
    validate_mixed_published_six_journals(source, append, children)
    workspaces = {provider: _prior_workspace(initial, provider,
        recognize_mixed_initial_apply_terminal(jobs.get(_child_id(core_id, provider)), initial, provider))
        for provider in order}
    return source, initial, append, generation, workspaces


def _topology(source):
    middles, edges, providers, proxies = {}, {}, {}, {}
    for index, chain in enumerate(source.chains):
        middle = chain.nodes[0]
        proxies[chain.assigned_proxy] = source.proxy_egress_ips[index]
        middles[middle["terraformAddress"]] = Middle(middle["publicIp"], chain.assigned_proxy)
        for node in chain.nodes:
            providers[node["terraformAddress"]] = node["provider"]
        for node in chain.nodes[1:]:
            edges[node["terraformAddress"]] = Edge(node["publicIp"], middle["terraformAddress"])
    return Topology(proxies, middles, edges), providers


def _route(source, channel, jobs):
    candidates = [(chain, node) for chain in source.chains for node in chain.nodes[1:]
                  if node["hostname"] == channel.get("edge")
                  and chain.chain_id == channel.get("chainId")]
    if len(candidates) != 1:
        raise ValueError("keyed channel edge is outside the published generation")
    chain, edge = candidates[0]
    middle = chain.nodes[0]
    core_id, details = active_core_connection_details(jobs, source.engagement_id)
    # The frozen six-host source binds each canonical proxy to its core public
    # identity. UI rows use the recorded engagement-qualified label instead.
    proxies = [row for row in details if row.get("role") == "proxy"
               and row.get("publicIp") == source.proxy_egress_ips[source.chains.index(chain)]]
    identity = core_proxy_identity(proxies, chain.assigned_proxy) if len(proxies) == 1 else {}
    if (core_id != source.core_job_id or len(proxies) != 1
            or not identity or not identity["displayName"]
            or proxies[0].get("sshAlias") != identity["displayName"]
            or channel.get("middle") != middle["hostname"]
            or channel.get("proxy") not in {chain.assigned_proxy, identity["displayName"]}):
        raise ValueError("keyed channel selected predecessor differs")
    external = int(channel["externalPort"])
    web = channel.get("mode") in {"http-openresty", "https-openresty"}
    relay = external if web else int(channel.get("middleRelayPort") or channel.get("relayPort") or 0)
    return KeyedRouteIntent(str(channel["channelId"]), "web" if web else str(channel["protocol"]).lower(),
                            edge["terraformAddress"], middle["terraformAddress"], external,
                            relay, ("0.0.0.0/0",))


def _prior_host_routes(source, jobs):
    pending = [event.data for job in jobs.list_for_engagement(source.engagement_id)
               for event in job.events if event.message == HOST_EVENT
               and event.data.get("sourceSha256") == source.source_sha256
               and event.data.get("changed") is not False]
    routes = ()
    while pending:
        ready = [row for row in pending if row.get("priorRoutesSha256") == _digest([asdict(r) for r in routes])]
        if len(ready) != 1:
            raise ValueError("keyed host policy history is disconnected or forked")
        row = ready[0]
        routes = tuple(KeyedRouteIntent(**{**r, "public_sources": tuple(r["public_sources"])})
                       for r in row["routes"])
        from app.services.provider_keyed_channel_generation import require_channel_host_proof
        require_channel_host_proof(source, row["hostProof"], routes)
        pending.remove(row)
    return routes


def _spec(source, index, policies, jobs, *, host_index=2):
    chain = source.chains[index]
    homebase, proxy = _core_hosts(jobs, source.engagement_id, chain.assigned_proxy,
                                  require_proxy_public_alias=True)
    middle, edges = _sketch_nodes(chain, require_exact_roles=True)
    root = Path(source.workspace_paths[index])
    unused = str(root / ".unused-channel-key")
    return SketchBootstrapSpec(homebase, proxy, middle, edges, unused, unused, unused, unused,
        unused, {node["hostname"]: policies[node["terraformAddress"]] for node in chain.nodes},
        source.proxy_egress_ips[index], str(six_host_known_hosts_path(source, index, host_index)),
        source.core_known_hosts_path)


def _callbacks(record, fence, label):
    def intended(value):
        fence()
        record("keyed channel routed command intended", {"phase": label,
               "invocationId": value.invocation_id, "argvSha256": value.argv_sha256})
    def started(value):
        fence()
        record("keyed channel routed command started", {"phase": label,
            "invocationId": value.intent.invocation_id, "bootId": value.identity.boot_id,
            "pid": value.identity.pid, "pgid": value.identity.pgid,
            "startTicks": value.identity.start_ticks})
    def completed(value):
        fence()
        record("keyed channel routed command completed", {"phase": label,
            "invocationId": value.started.intent.invocation_id, "returnCode": value.returncode,
            "stdoutTruncated": value.stdout_truncated, "stderrTruncated": value.stderr_truncated})
    return dict(on_intent=intended, on_started=started,
                on_heartbeat=lambda _value: fence(), on_result=completed)


def _prove_hosts(source, policies, jobs, job_id, phase, fence, record):
    captures = []
    for index, chain in enumerate(source.chains):
        for host_index, node in enumerate(chain.nodes):
            fence()
            spec = _spec(source, index, policies, jobs, host_index=host_index)
            known_sha = hashlib.sha256(_read(Path(spec.initial_sketch_known_hosts_path))).hexdigest()
            captured = _probe_cross_provider_edge(source, index, spec,
                scratch=Path(source.workspace_paths[index]) / f".barragan-channel-probe-{uuid4().hex}",
                sketch_known_hosts_sha256=known_sha, fence=fence,
                on_scratch=lambda value: record("keyed channel private probe scratch", {"path": value}),
                host_index=host_index, expected_policy=policies[node["terraformAddress"]],
                **_callbacks(record, fence, phase))
            captures.append(asdict(captured))
    path = Path(source.workspace_paths[0]) / f".barragan-channel-{job_id}-{phase}.json"
    if path.exists() or path.is_symlink():
        raise ValueError("keyed channel host proof already exists; inspect its job")
    _write_private_json(path, {"sourceSha256": source.source_sha256,
                      "policySha256": _digest(policies), "captures": captures})
    return {"path": str(path), "sha256": hashlib.sha256(_read(path)).hexdigest()}


def _converge_hosts(source, before, after, jobs, fence, record):
    for index, chain in enumerate(source.chains):
        changes = []
        for node in chain.nodes:
            address = node["terraformAddress"]
            old = {tuple(sorted(rule.items())) for rule in before[address]["sketch_firewall_v2_rules"]}
            new = {tuple(sorted(rule.items())) for rule in after[address]["sketch_firewall_v2_rules"]}
            changes.extend((node, "delete", dict(rule)) for rule in sorted(old - new))
            changes.extend((node, "allow", dict(rule)) for rule in sorted(new - old))
        if not changes:
            continue
        with _policy_scratch(source.workspace_paths[index]) as root:
            private, _ = write_existing_sketch_ssh_key_files(source.engagement_id, root / "keys")
            config = root / "ssh.conf"
            for node, operation, rule in changes:
                fence()
                spec = _spec(source, index, after, jobs, host_index=chain.nodes.index(node))
                config.write_text(render_strict_v2_sketch_identity_ssh_config(
                    replace(spec, admin_private_key_path=str(private))))
                config.chmod(0o600)
                words = ["sudo", "-n", "ufw"]
                words += ["--force", "delete", "allow"] if operation == "delete" else ["allow"]
                words += ["proto", rule["proto"], "from", rule["from_ip"], "to", "any", "port", str(rule["port"])]
                callbacks = _callbacks(record, fence, "host-policy")
                result = run_gated_command(["/usr/bin/ssh", "-F", str(config),
                    f"barragan-bootstrap-user-{node['hostname']}", shlex.join(words)],
                    scratch_path=root, provider_keyed_v2=True, env=barragan_subprocess_env(),
                    intent_callback=callbacks["on_intent"], started_callback=callbacks["on_started"],
                    heartbeat_callback=callbacks["on_heartbeat"], result_callback=callbacks["on_result"])
                if result.returncode or result.stdout_truncated or result.stderr_truncated:
                    raise ValueError("keyed host policy command requires observation")


@contextmanager
def _policy_scratch(parent):
    root = Path(tempfile.mkdtemp(prefix=".barragan-channel-policy-", dir=parent))
    root.chmod(0o700)  # Clear setgid inherited from the shared provider workspace.
    uncertain = False
    try:
        yield root
    except UnreapedGatedCommandError:
        uncertain = True
        raise
    finally:
        if not uncertain:
            shutil.rmtree(root)



def _prove_provider_generation(provider, policy, workspace, credentials, fence, *, wait_for_completion=False):
    from app.integrations.linode_validation import UrllibLinodeTransport
    from app.services.provider_catalog import UrllibProviderCatalogTransport
    from app.services.credentials import decrypt_secret_value
    raw = _read(workspace.state_path, private=False)
    _, resources, cloud = _state(provider, policy, raw)
    token = decrypt_secret_value(_credential(credentials, provider, policy))
    if provider == "linode":
        rows, attached = _linode(_FencedLinodeTransport(UrllibLinodeTransport(), fence, fence()), token, fence, policy)
        if set(attached) != {str(resources[a]["id"]) for a in policy["nodes"]}:
            raise ValueError("keyed Linode attachment differs")
    else:
        rows, exists, count, attached = _digitalocean(
            _FencedDigitalOceanTransport(UrllibProviderCatalogTransport(), fence, fence()),
            token, policy["selector_tag"], fence)
        if not exists or count != len(policy["nodes"]) or set(attached) != {
                str(resources[a]["id"]) for a in policy["nodes"]}:
            raise ValueError("keyed DigitalOcean selector differs")
    _inventory(provider, policy, resources, cloud, rows)
    require_current_keyed_firewall(provider, policy, resources, fence=fence,
                                   credential_repository=credentials,
                                   wait_for_completion=wait_for_completion)

def sync_keyed_channel_apply(engagement_id, channel, *, jobs, record):
    """Run inside ordinary Apply's already-held engagement mutation lease."""
    if runtime_value("ENVIRONMENT") != "devtest":
        raise ValueError("keyed channels are DevTest-only")
    source, initial, append, generation, workspaces = load_keyed_channel_source(engagement_id, jobs)
    owner = _active_mutation_owner.get()
    lease = _db_lease_lookup(engagement_id)
    if not owner or lease is None or lease[0] != owner or not lease[1].startswith("inbound_channel_"):
        raise ValueError("keyed channel engagement mutation lease differs")
    current = next((job for job in jobs.list_for_engagement(engagement_id)
                    if job.id == record.job_id), None)
    if current is None or current.status != "running" or current.action != "inbound_channel_apply":
        raise ValueError("keyed channel running job differs")
    expected_hashes = dict(zip(source.provider_order, generation.state_sha256s))
    expected_heads = dict(generation.receipt_heads)
    chain_rows = tuple(SqlAlchemySketchChainRepository().list_for_engagement(engagement_id))

    def fence(*, check_states=True):
        if (_db_lease_lookup(engagement_id) != lease
                or jobs.get(initial.id) != initial or jobs.get(append.id) != append
                or tuple(SqlAlchemySketchChainRepository().list_for_engagement(engagement_id)) != chain_rows
                or active_core_connection_details(jobs, engagement_id)[0] != source.core_job_id
                or jobs.get(current.id).status != "running"
                or hashlib.sha256(_read(Path(source.core_known_hosts_path), private=False)).hexdigest() != source.core_known_hosts_sha256):
            raise ValueError("keyed channel source or lease changed")
        if read_channel_generation(source, append, initial, jobs,
                                   require_current_state=False).receipt_heads != expected_heads:
            raise ValueError("keyed channel predecessor receipt changed")
        if check_states and any(hashlib.sha256(_read(workspaces[p].state_path, private=False)).hexdigest()
                                != expected_hashes[p] for p in source.provider_order):
            raise ValueError("keyed channel state changed")
        return source.source_sha256

    topology, providers = _topology(source)
    prior = _prior_host_routes(source, jobs)
    selected = _route(source, channel, jobs)
    desired = tuple(sorted((*[row for row in prior if row.channel_id != selected.channel_id], selected),
                           key=lambda row: row.channel_id))
    before = render_keyed_route_projection(topology, providers, prior)
    after = render_keyed_route_projection(topology, providers, desired)
    credentials = SqlAlchemyCredentialRepository()

    def provider_proof(provider, policy, *, post=False):
        check = (lambda: fence(check_states=False)) if post else fence
        return _prove_provider_generation(provider, policy, workspaces[provider], credentials, check,
                                          wait_for_completion=post)

    fence()
    for provider in source.provider_order:
        provider_proof(provider, generation.policies[provider])
    _prove_hosts(source, before.host_policies, jobs, current.id, "before", fence, record)
    _converge_hosts(source, before.host_policies, after.host_policies, jobs, fence, record)
    proof = _prove_hosts(source, after.host_policies, jobs, current.id, "after", fence, record)
    record(HOST_EVENT, {"sourceSha256": source.source_sha256, "changed": desired != prior,
           "priorRoutesSha256": _digest([asdict(row) for row in prior]),
           "routes": [asdict(row) for row in desired], "hostProof": proof})
    updates = []
    for provider in source.provider_order:
        old_routes, next_routes = generation.provider_routes[provider], after.provider_routes[provider]
        if old_routes == next_routes:
            continue
        workspace, policy = workspaces[provider], generation.policies[provider]
        variables = dict(policy["nonsecret_varfile"])
        tcp = sorted({row.port for row in next_routes if row.protocol == "tcp"})
        variables.update(allowed_tcp_ports=["22", "80", "443", "2222"] + [str(p) for p in tcp],
                         allowed_udp_ports=[str(p) for p in sorted({r.port for r in next_routes if r.protocol == "udp"})])
        addresses = tuple(sorted(policy["nodes"]))
        observed = {address: tuple(sorted({(rule["proto"], rule["port"])
            for rule in after.host_policies[address]["sketch_firewall_v2_rules"]
            if rule["port"] not in {80, 443, 2222}})) for address in addresses}
        update = KeyedIngressUpdate(workspace, current.id, selected.channel_id,
            _state_resources(json.loads(_read(workspace.state_path, private=False))), old_routes, next_routes,
            addresses, observed, policy["nonsecret_varfile"], variables,
            generation.input_paths[provider], hashlib.sha256(_read(generation.input_paths[provider])).hexdigest(),
            expected_hashes[provider], _digest(read_provider_topology(workspace)),
            predecessor_receipt_sha256=generation.receipt_heads[provider])
        plan_keyed_ingress_update(update, credentials=credentials, recheck_authority=fence,
                                  command_environment=barragan_subprocess_env(),
                                  staged_admin_material=lambda update=update: _staged_append_admin_material(
                                      append, update.workspace, update.reviewed_variables, jobs))
        updates.append((provider, update, {**policy, "nonsecret_varfile": variables}))
    # Both plans are approved before the first provider write.
    for provider, update, policy in updates:
        def authority():
            fence()
            provider_proof(provider, generation.policies[provider])
        receipt = apply_keyed_ingress_update(update, credentials=credentials,
            recheck_authority=authority,
            post_apply_proof=lambda: provider_proof(provider, policy, post=True),
            command_environment=barragan_subprocess_env(),
            staged_admin_material=lambda update=update: _staged_append_admin_material(
                append, update.workspace, update.reviewed_variables, jobs))
        status, inputs, _, _ = _paths(update)
        record(EVENT, {"sourceSha256": source.source_sha256, "jobId": current.id,
            "provider": provider, "predecessorReceiptSha256": receipt["predecessorReceiptSha256"],
            "beforeStateSha256": expected_hashes[provider],
            "afterStateSha256": receipt["postStateSha256"],
            "receiptSha256": hashlib.sha256(_read(status)).hexdigest(),
            "inputSha256": hashlib.sha256(_read(inputs)).hexdigest(), "hostProof": proof})
        expected_hashes[provider] = receipt["postStateSha256"]
        expected_heads[provider] = hashlib.sha256(_read(status)).hexdigest()
    fence()
