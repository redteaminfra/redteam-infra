# Copyright (c) 2026, Oracle and/or its affiliates.
"""Real SQL publication -> central channel Apply -> generation/scope reopening.

Host/provider contacts, Terraform commands and the initial workspace/source
checkout are fixture witnesses. SQL append publication, channel source
recognition, leases, plan gates, retained receipt files, raw host interpretation
and generation/teardown scope validation execute normally.
"""
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_channel_apply as channel
from app.services import provider_keyed_ingress_update as ingress
from app.services import provider_keyed_ingress_plan_gate as gate
from app.services.inbound_mutation_fence import bind_inbound_mutation
from app.services.provider_keyed_channel_generation import read_channel_generation
from app.services.provider_keyed_ingress_route_ledger import KeyedRouteIntent
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_mixed_published_six_scope import build_mixed_published_six_teardown_scope
from app.services.provider_keyed_sketch import ProviderKeyedWorkspace, SCHEMA
from app.storage.database import db
from app.storage.job_repository import StoredJobRun, SqlAlchemyJobRepository
from app.storage.models import CoreMutationLeaseModel
from test_provider_keyed_channel_generation import case as generation_case, _public, _real_host_proof
import test_provider_keyed_mixed_published_six_integration as persisted


@pytest.fixture
def case(client, tmp_path, monkeypatch):
    original = persisted._policy_case
    def policy_case():
        source, approved, initial, policies, files = original()
        from app.services.provider_keyed_linode_udp_source_gate import _CANDIDATE_SOURCE_REVISION
        from app.services.provider_keyed_mixed_append_pair_plan_worker import _name
        source = replace(source,
            core_known_hosts_sha256=sha256(b"retained core trust").hexdigest(),
            source_revisions=tuple(_CANDIDATE_SOURCE_REVISION if p == "linode" else source.source_revisions[i]
                                   for i, p in enumerate(source.provider_order)))
        for provider in source.provider_order:
            material = tmp_path / ".plan-material" / provider
            material.mkdir(parents=True, mode=0o700)
            paths = {"ssh_pub_key_path": str(material / "admin-public"),
                     "ssh_priv_key_path": str(material / "admin-private")}
            approved.input["reviewedInputs"][provider].update(paths)
            approved.input["intents"][provider]["nonsecret_varfile"].update(paths)
            root = Path(source.workspace_paths[source.provider_order.index(provider)])
            raw = json.dumps(approved.input["reviewedInputs"][provider]).encode()
            files[root / _name(provider, "inputs.json")] = raw
            path = root / _name(provider, "plan-receipt.json")
            receipt = json.loads(files[path])
            receipt["inputSha256"] = sha256(raw).hexdigest()
            files[path] = json.dumps(receipt).encode()
        index = source.provider_order.index("linode")
        path = Path(source.workspace_paths[index]) / _name("linode", "plan-receipt.json")
        receipt = json.loads(files[path])
        receipt["sourceRevision"] = _CANDIDATE_SOURCE_REVISION
        files[path] = json.dumps(receipt).encode()
        return source, approved, initial, policies, files
    monkeypatch.setattr(persisted, "_policy_case", policy_case)
    original_publication = persisted.persisted_six_case
    monkeypatch.setattr(persisted, "persisted_six_case", lambda *args, **kwargs:
        original_publication(*args, **kwargs, sql_host=True, inert_history=True))
    iterator = generation_case.__wrapped__(client, tmp_path, monkeypatch)
    value = next(iterator)
    known = Path(value["source"].core_known_hosts_path)
    known.write_bytes(b"retained core trust")
    known.chmod(0o644)  # Public core host-key pins retain bootstrap permissions.
    try:
        yield value
    finally:
        next(iterator, None)


@pytest.mark.parametrize("chain_index", [0, 1])
@pytest.mark.parametrize("edge_index", [1, 2])
@pytest.mark.parametrize("kind", ["tcp", "udp", "http", "https"])
def test_sql_central_apply_and_six_teardown_reopen(case, tmp_path, monkeypatch,
                                                   chain_index, edge_index, kind):
    _sql_channel_workflow(case, tmp_path, monkeypatch, chain_index, edge_index, kind)


@pytest.mark.parametrize('batch_failure', [False, True])
def test_sql_raw_then_two_http_then_https_batch_preserves_source_history_and_parent_lease(case, tmp_path, monkeypatch, batch_failure):
    _sql_channel_workflow(case, tmp_path, monkeypatch, 0, 2, 'udp', sequence=True, batch_failure=batch_failure)


@pytest.mark.parametrize('guard_drift', ['missing-lease', 'foreign-owner', 'wrong-operation', 'missing-context', 'failed-child', 'wrong-child-action', 'missing-child'])
def test_sql_keyed_batch_guards_reject_before_any_external_command(case, tmp_path, monkeypatch, guard_drift):
    _sql_channel_workflow(case, tmp_path, monkeypatch, 0, 2, 'https', guard_drift=guard_drift)


@pytest.mark.parametrize('noop_metadata', [False, True])
def test_sql_consecutive_noop_receipts_retry_and_later_write_reopen(case, tmp_path, monkeypatch, noop_metadata):
    _sql_channel_workflow(case, tmp_path, monkeypatch, 1, 1, 'udp', dns_history=True, noop_metadata=noop_metadata)


def _sql_channel_workflow(case, tmp_path, monkeypatch, chain_index, edge_index, kind, *, sequence=False, batch_failure=False, guard_drift=None, dns_history=False, noop_metadata=False):
    source, jobs = case["source"], case["jobs"]
    initial = case["initial"]
    now = datetime.now(timezone.utc).isoformat()
    job = jobs.save(StoredJobRun("job-channel-connected", "inbound_channel_apply", "running",
        f"engagement:{source.engagement_id}", "engagement", source.engagement_id,
        "operator", {"engagementId": source.engagement_id, "channelId": "channel"},
        [], now, now, None, [JobEvent(1, "info", "inbound Apply started", {})]))
    db.session.add(CoreMutationLeaseModel(engagement_id=source.engagement_id,
        owner_id=job.id, operation="inbound_channel_apply"))
    db.session.commit()
    monkeypatch.setattr(channel, "runtime_value", lambda _: "devtest")
    monkeypatch.setattr(channel, "active_core_connection_details", lambda *_: (source.core_job_id, [
        dict(role='proxy', displayName=chain.assigned_proxy + '-c4e91b20',
             sshAlias=chain.assigned_proxy + '-c4e91b20', publicIp=source.proxy_egress_ips[index])
        for index, chain in enumerate(source.chains)]))
    # The initial-provider workspace receipt is separately covered by initial
    # publication tests; this fixture starts at real append publication.
    workspaces = {}
    for index, provider in enumerate(source.provider_order):
        root = Path(source.workspace_paths[index])
        (root / ".terraform-data").mkdir(exist_ok=True)
        from app.services.provider_keyed_mixed_append_pair_plan_worker import _name
        receipt = json.loads((root / _name(provider, "plan-receipt.json")).read_bytes())
        workspaces[provider] = ProviderKeyedWorkspace(root, root / "terraform.tfstate",
            root / ".terraform-data", SCHEMA, provider, "cred", "fingerprint",
            source.source_revisions[index], receipt["sourceSha256"])
    from test_provider_keyed_mixed_append_pair_apply_binding import _admin_key_setup
    sealed_public, sealed_private, _ = _admin_key_setup(monkeypatch, workspaces)
    monkeypatch.setattr(channel, "recognize_mixed_initial_apply_terminal", lambda *_: {})
    monkeypatch.setattr(channel, "_prior_workspace", lambda _i, p, _t: workspaces[p])
    # Preserve exact topology bytes/hash in every production fence.
    monkeypatch.setattr(channel, "_prove_provider_generation", lambda _p, _policy, _w, _c, fence, **kwargs: fence())
    monkeypatch.setattr(channel, "_converge_hosts", lambda _s, _b, _a, _j, fence, _r: fence())
    selected_chain = source.chains[chain_index]
    selected = selected_chain.nodes[edge_index]
    web = kind in {"http", "https"}
    external = 80 if kind == "http" else 443 if kind == "https" else 53 if dns_history else 18301
    relay = external if web else 8004
    route = KeyedRouteIntent("channel", "web" if web else kind, selected["terraformAddress"],
        selected_chain.nodes[0]["terraformAddress"], external, relay, ("0.0.0.0/0",))
    proof_routes = {'before': (), 'after': (route,)}
    def hosts(_s, policies, _j, job_id, phase, fence, record):
        fence()
        # This fixture produces raw six-host captures; the normal interpreter
        # must accept them when generation history reopens below.
        path, _ = _real_host_proof(case, jobs.get(job_id),
            proof_routes[phase], monkeypatch)
        return {"path": str(path), "sha256": sha256(path.read_bytes()).hexdigest()}
    monkeypatch.setattr(channel, "_prove_hosts", hosts)
    monkeypatch.setattr(ingress, "_audit", lambda _: None)
    monkeypatch.setattr(gate, "require_linode_workspace", lambda _: None)
    monkeypatch.setattr(gate, "require_digitalocean_workspace", lambda _: None)
    monkeypatch.setattr(gate, "require_candidate_linode_udp_workspace", lambda _: None)
    monkeypatch.setattr(ingress, "_credential", lambda _w, _c: ("2" * 64, "2026-10-19T00:00:00Z", "token"))
    binary = tmp_path / "terraform"
    binary.write_bytes(b"offline command-boundary witness")
    binary.chmod(0o700)
    release = lambda **_: SimpleNamespace(path=binary, sha256=sha256(binary.read_bytes()).hexdigest(), version="1.15.5")
    plans, calls = {}, []
    fail_next_plan = {"value": False}
    head_drift = {'stage': None, 'saved': None}
    def inject_head_drift(stage):
        if head_drift['stage'] != stage:
            return
        head_drift['stage'] = None
        provider = source.chains[0].nodes[2]['provider']
        target = jobs.get('job-dns-3-0')
        original_heads = read_channel_generation(source, case['append_parent'], initial, jobs).receipt_heads
        head_drift['saved'] = target
        jobs.save(replace(target, events=[e for e in target.events
            if not (e.message == channel.EVENT and e.data['provider'] == provider)]))
        drifted = read_channel_generation(source, case['append_parent'], initial, jobs)
        assert drifted.receipt_heads != original_heads
        assert all(sha256(w.state_path.read_bytes()).hexdigest() == drifted.state_sha256s[source.provider_order.index(p)]
                   for p, w in workspaces.items())
    real_plan, real_apply = ingress.plan_keyed_ingress_update, ingress.apply_keyed_ingress_update
    def plan(update, **kwargs):
        inject_head_drift('plan')
        provider = update.workspace.provider
        before = deepcopy(dict(update.retained_resources))
        firewall = f"{provider}_firewall.firewall"
        field = "inbound" if provider == "linode" else "inbound_rule"
        after = deepcopy(before)
        public = {("tcp", p) for p in (80, 443, 2222)} | {(r.protocol, r.port) for r in update.next_routes}
        after[firewall][field] = [_public(provider, proto, port) for proto, port in sorted(public)]
        variables = {**update.reviewed_variables, "do_pat" if provider == "digitalocean" else "linode_api_token": "token"}
        noop = before == after
        shown = {"format_version": "1.2", "terraform_version": "1.15.5", "applyable": not noop,
            "complete": True, "errored": False, "resource_drift": [],
            "variables": {key: {"value": value} for key, value in variables.items()},
            "prior_state": {"values": {"root_module": {"resources": [
                {"address": a, "mode": "managed", "values": v} for a, v in before.items()]}}},
            "resource_changes": [{"address": a, "mode": "managed", "change": {
                "actions": ["update"] if a == firewall and not noop else ["no-op"], "before": v,
                "after": after[a], "after_unknown": {}, "before_sensitive": {}, "after_sensitive": {}}}
                for a, v in before.items()]}
        if fail_next_plan['value']:
            fail_next_plan['value'] = False
            shown['applyable'] = not shown['applyable']
        plans[provider] = (shown, after)
        return real_plan(update, **kwargs, release_validator=release, command_runner=runner)
    def runner(argv, root, env):
        provider = next(p for p, w in workspaces.items() if w.path == root)
        variables = plans[provider][0]["variables"]
        # Model the upstream literal file() read at every command boundary.
        public = Path(variables["ssh_pub_key_path"]["value"])
        private = Path(variables["ssh_priv_key_path"]["value"])
        assert public.read_text() == sealed_public
        assert private.read_text() == sealed_private
        assert public.stat().st_mode & 0o777 == private.stat().st_mode & 0o777 == 0o600
        calls.append((provider, argv[1]))
        if argv[1] == "plan":
            Path(next(arg[5:] for arg in argv if arg.startswith("-out="))).write_bytes(b"saved binary")
        if argv[1] == "apply" and (plans[provider][0]['applyable'] or noop_metadata):
            state = json.loads((root / "terraform.tfstate").read_bytes())
            for address, attrs in _state_resources(state).items():
                attrs.clear(); attrs.update(plans[provider][1][address])
            state["serial"] += 1
            if noop_metadata and not plans[provider][0]['applyable']:
                state['check_results'].reverse()
            (root / "terraform.tfstate").write_text(json.dumps(state))
        return subprocess.CompletedProcess(argv, 0,
            json.dumps(plans[provider][0]) if argv[1] == "show" else "", "")
    monkeypatch.setattr(channel, "plan_keyed_ingress_update", plan)
    def apply(update, **kwargs):
        inject_head_drift('apply')
        return real_apply(update, **kwargs, release_validator=release, command_runner=runner)
    monkeypatch.setattr(channel, "apply_keyed_ingress_update", apply)
    def record(message, data):
        current = jobs.get(job.id)
        jobs.save(replace(current, events=[*current.events, JobEvent(len(current.events) + 1, "info", message, data)]))
    record.job_id = job.id
    pending = {"channelId": "channel", "chainId": selected_chain.chain_id,
        "edge": selected["hostname"], "middle": selected_chain.nodes[0]["hostname"],
        "proxy": selected_chain.assigned_proxy + '-c4e91b20',
        "mode": f"{kind}-openresty" if web else f"{kind}-forward",
        "protocol": "TCP" if web else kind.upper(),
        "externalPort": str(external), "middleRelayPort": str(relay)}
    if guard_drift:
        lease_row = CoreMutationLeaseModel.query.get(source.engagement_id)
        if guard_drift == 'missing-lease':
            db.session.delete(lease_row)
        elif guard_drift == 'foreign-owner':
            lease_row.owner_id = 'job-foreign'
        elif guard_drift == 'wrong-operation':
            lease_row.operation = 'core_deployment'
        db.session.commit()
        if guard_drift in {'failed-child', 'wrong-child-action'}:
            jobs.save(replace(job, **({'status': 'failed'} if guard_drift == 'failed-child' else {'action': 'other'})))
        if guard_drift == 'missing-child':
            record.job_id = 'job-missing'
        with bind_inbound_mutation('' if guard_drift == 'missing-context' else job.id):
            with pytest.raises(ValueError, match='lease differs|running job differs'):
                channel.sync_keyed_channel_apply(source.engagement_id, pending, jobs=jobs, record=record)
        assert calls == []
        assert not any(event.message == channel.HOST_EVENT for event in jobs.get(job.id).events)
        return
    immutable = asdict(source)
    with bind_inbound_mutation(job.id):
        channel.sync_keyed_channel_apply(source.engagement_id, pending, jobs=jobs, record=record)
    for workspace in workspaces.values():
        material = workspace.path.parents[1] / ".plan-material" / workspace.provider
        assert not (material / "admin-public").exists()
        assert not (material / "admin-private").exists()
    if web:
        assert calls == []  # Provider baseline already exposes fixed 80/443.
    else:
        assert max(i for i, c in enumerate(calls) if c[1] == "plan") < min(i for i, c in enumerate(calls) if c[1] == "apply")
    # This loads persisted SQL events and runs the actual raw-host interpreter.
    assert channel._prior_host_routes(source, jobs) == (route,)
    reopened = read_channel_generation(source, case["append_parent"], initial, jobs)
    assert len(reopened.advances) == (0 if web else edge_index)
    assert asdict(source) == immutable
    if sequence:
        from app.services import inbound_channel_apply as entry
        from app.services import inbound_channel_batch as batch
        from app.services.inbound_mutation_fence import active_inbound_mutation_owner
        from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
        leases = SqlAlchemyDeploymentPlanRepository()
        leases.release(source.engagement_id, job.id)
        parent_id = 'job-batch-connected'
        leases.acquire(source.engagement_id, parent_id, 'inbound_channel_batch_apply')
        channels = []
        for identity, port in (('http-a', 80), ('http-b', 80), ('https-a', 443)):
            channels.append({**pending, 'channelId': identity, 'mode': 'https-openresty' if port == 443 else 'http-openresty',
                'protocol': 'TCP', 'externalPort': str(port), 'middleRelayPort': str(port),
                'validationProfile': {'type': 'manual'}})
        parent = jobs.save(StoredJobRun(parent_id, 'inbound_channel_batch_apply', 'queued',
            f'engagement:{source.engagement_id}', 'engagement', source.engagement_id, 'operator',
            {'engagementId': source.engagement_id, 'children': [dict(channelId=c['channelId'], status='queued') for c in channels]},
            [], now, None, None, []))
        prepared_owners = []
        releases = []
        real_release = leases.release
        def release(engagement_id, owner_id):
            releases.append((owner_id, jobs.get(parent_id).status))
            return real_release(engagement_id, owner_id)
        monkeypatch.setattr(leases, 'release', release)
        def prepare(engagement_id, channel_id, **kwargs):
            assert active_inbound_mutation_owner() == parent_id
            assert channel._db_lease_lookup(engagement_id) == (parent_id, 'inbound_channel_batch_apply')
            if batch_failure and channel_id == 'http-b':
                raise ValueError('offline preparation failed')
            prior_routes = channel._prior_host_routes(source, jobs)
            selected_channel = kwargs['channel']
            selected_route = channel._route(source, selected_channel, jobs)
            proof_routes['before'] = prior_routes
            proof_routes['after'] = tuple(sorted((*prior_routes, selected_route), key=lambda row: row.channel_id))
            prepared_owners.append(parent_id)
            child = jobs.save(StoredJobRun(f'job-{channel_id}', 'inbound_channel_apply', 'running',
                f'engagement:{engagement_id}', 'engagement', engagement_id, 'operator',
                {'engagementId': engagement_id, 'channelId': channel_id}, [], now, now, None,
                [JobEvent(1, 'info', 'offline route preparation fixture', {})]))
            return jobs, child, [], tmp_path, None, selected_channel, selected_chain.chain_id, 'fixture'
        monkeypatch.setattr(entry, '_prepare_inbound_apply_job', prepare)
        monkeypatch.setattr(entry, '_keyed_engagement', lambda _: True)
        monkeypatch.setattr(entry, '_merged_inbound_channels', lambda _e, _id, selected: [selected])
        monkeypatch.setattr(entry, 'try_enqueue_infra_orientation_refresh', lambda *args, **kwargs: None)
        # Real batch, entry points, keyed source/lease/history guard, completion
        # writer and parent finally-release. Heavy preparation/route command
        # execution is the explicit external/render seam, not authority proof.
        batch._run_parent_guarded(jobs, parent.id, source.engagement_id, channels, 'operator', leases)
        assert jobs.get(parent.id).status == ('failed' if batch_failure else 'succeeded')
        assert len(prepared_owners) == (1 if batch_failure else 3)
        if batch_failure:
            assert jobs.get('job-http-a').status == 'succeeded'
            assert jobs.get('job-http-b') is None and jobs.get('job-https-a') is None
        else:
            assert all(jobs.get(f"job-{c['channelId']}").status == 'succeeded' for c in channels)
        assert channel._db_lease_lookup(source.engagement_id) is None
        assert releases == [(parent_id, 'failed' if batch_failure else 'succeeded')]
        final_routes = channel._prior_host_routes(source, jobs)
        assert [row.channel_id for row in final_routes] == (['channel', 'http-a'] if batch_failure else ['channel', 'http-a', 'http-b', 'https-a'])
        reopened = read_channel_generation(source, case['append_parent'], initial, jobs)
        assert len(reopened.advances) == edge_index  # Host-only web does not add cloud writes.

    if dns_history:
        from app.services.provider_keyed_channel_generation import EVENT
        from app.services.terraform_plan_gate import TerraformPlanGateError
        from app.storage.deployment_plan_repository import SqlAlchemyDeploymentPlanRepository
        leases = SqlAlchemyDeploymentPlanRepository()
        jobs.save(replace(jobs.get(job.id), status='succeeded', finished_at=now))
        leases.release(source.engagement_id, job.id)
        original_source = asdict(source)
        noops = []
        for number, (ci, ei, port, relay_port, identity) in enumerate([
                (1, 1, 54, 8005, 'seed-second'),
                (0, 2, 53, 8006, 'new-dns-a'),
                (0, 2, 54, 8007, 'new-dns-b'),
                (0, 2, 55, 8008, 'later-write')], 1):
            chain = source.chains[ci]
            node = chain.nodes[ei]
            candidate = {**pending, 'channelId': identity, 'chainId': chain.chain_id,
                         'edge': node['hostname'], 'middle': chain.nodes[0]['hostname'],
                         'proxy': chain.assigned_proxy + '-c4e91b20',
                         'externalPort': str(port), 'middleRelayPort': str(relay_port)}
            attempts = (0, 1) if number == 2 else (0, 1, 2) if number == 4 and not noop_metadata else (0,)
            for attempt in attempts:
                job_id = f'job-dns-{number}-{attempt}'
                job = jobs.save(StoredJobRun(job_id, 'inbound_channel_apply', 'running',
                    f'engagement:{source.engagement_id}', 'engagement', source.engagement_id,
                    'operator', {'engagementId': source.engagement_id, 'channelId': identity},
                    [], now, now, None, [JobEvent(1, 'info', 'inbound Apply started', {})]))
                leases.acquire(source.engagement_id, job.id, 'inbound_channel_apply')
                record.job_id = job.id
                prior_host_routes = channel._prior_host_routes(source, jobs)
                next_host_routes = (*tuple(r for r in prior_host_routes if r.channel_id != identity),
                    KeyedRouteIntent(identity, 'udp', node['terraformAddress'], chain.nodes[0]['terraformAddress'],
                                     port, relay_port, ('0.0.0.0/0',)))
                next_host_routes = tuple(sorted(next_host_routes, key=lambda row: row.channel_id))
                proof_routes.update(before=prior_host_routes, after=next_host_routes)
                state_before = {p: w.state_path.read_bytes() for p, w in workspaces.items()}
                if number == 4 and attempt < 2 and not noop_metadata:
                    calls_before = calls.count((source.provider_order[0], 'apply')) + calls.count((source.provider_order[1], 'apply'))
                    head_drift['stage'] = 'plan' if attempt == 0 else 'apply'
                    with bind_inbound_mutation(job.id), pytest.raises(ValueError, match='predecessor receipt changed'):
                        channel.sync_keyed_channel_apply(source.engagement_id, candidate, jobs=jobs, record=record)
                    assert calls.count((source.provider_order[0], 'apply')) + calls.count((source.provider_order[1], 'apply')) == calls_before
                    assert all(w.state_path.read_bytes() == state_before[p] for p, w in workspaces.items())
                    jobs.save(head_drift['saved'])  # Restore test-only race injection.
                    jobs.save(replace(jobs.get(job.id), status='failed', finished_at=now))
                    leases.release(source.engagement_id, job.id)
                    continue
                if number == 2 and attempt == 0:
                    fail_next_plan['value'] = True
                    with bind_inbound_mutation(job.id), pytest.raises(TerraformPlanGateError):
                        channel.sync_keyed_channel_apply(source.engagement_id, candidate, jobs=jobs, record=record)
                    jobs.save(replace(jobs.get(job.id), status='failed', finished_at=now))
                    assert channel._prior_host_routes(source, jobs) == next_host_routes
                    assert all(w.state_path.read_bytes() == state_before[p] for p, w in workspaces.items())
                    assert not any(e.message == EVENT for e in jobs.get(job.id).events)
                    failed_job = jobs.get(job.id)
                    leases.release(source.engagement_id, job.id)
                    continue
                with bind_inbound_mutation(job.id):
                    channel.sync_keyed_channel_apply(source.engagement_id, candidate, jobs=jobs, record=record)
                jobs.save(replace(jobs.get(job.id), status='succeeded', finished_at=now))
                leases.release(source.engagement_id, job.id)
                reopened = read_channel_generation(source, case['append_parent'], initial, jobs)
                # New repository/session facade reopens persisted SQL plus immutable files.
                restarted = read_channel_generation(source, case['append_parent'], initial, SqlAlchemyJobRepository())
                assert restarted == reopened and asdict(source) == original_source
                for event in jobs.get(job.id).events:
                    if event.message != EVENT:
                        continue
                    provider = event.data['provider']
                    if number in {2, 3} and provider == node['provider']:
                        assert (event.data['beforeStateSha256'] == event.data['afterStateSha256']) is (not noop_metadata)
                        if noop_metadata:
                            ingress._require_noop_state(state_before[provider], workspaces[provider].state_path.read_bytes())
                        else:
                            assert workspaces[provider].state_path.read_bytes() == state_before[provider]
                        noops.append(event.data)
                assert channel._prior_host_routes(source, jobs) == next_host_routes
        assert len(noops) == 2
        assert jobs.get(failed_job.id) == failed_job  # No artifact/history repair or replay.
        # Fork/stripped/foreign/downgraded receipts cannot borrow the same state hash.
        current = jobs.get('job-dns-3-0')
        original_events = current.events
        ix = next(i for i, e in enumerate(original_events) if e.message == EVENT
                  and e.data['provider'] == source.chains[0].nodes[2]['provider'])
        receipt_path = Path(source.workspace_paths[source.provider_order.index(original_events[ix].data['provider'])]) / f'.barragan-ingress-{current.id}-status.json'
        original_receipt = receipt_path.read_bytes()
        for drift in ('fork', 'missing-head', 'foreign-head', 'wrong-provider', 'duplicate', 'downgrade'):
            events = list(original_events)
            if drift in {'fork', 'duplicate'}:
                events.append(replace(events[ix], sequence=len(events)+1))
            else:
                data = dict(events[ix].data)
                if drift == 'downgrade':
                    data.pop('predecessorReceiptSha256')
                    value = json.loads(original_receipt)
                    value.pop('predecessorReceiptSha256')
                    value['schema'] = 'keyed-ingress-update-v1'
                    receipt_path.write_text(json.dumps(value))
                    data['receiptSha256'] = sha256(receipt_path.read_bytes()).hexdigest()
                elif drift == 'missing-head':
                    data.pop('predecessorReceiptSha256')
                elif drift == 'foreign-head':
                    data['predecessorReceiptSha256'] = 'f' * 64
                else:
                    data['provider'] = next(p for p in source.provider_order if p != data['provider'])
                events[ix] = replace(events[ix], data=data)
            jobs.save(replace(current, events=events))
            with pytest.raises(ValueError):
                read_channel_generation(source, case['append_parent'], initial, jobs)
            receipt_path.write_bytes(original_receipt)
        jobs.save(replace(current, events=original_events))
        reopened = read_channel_generation(source, case['append_parent'], initial, jobs)

    observations = {}
    for index, provider in enumerate(source.provider_order):
        raw = workspaces[provider].state_path.read_bytes()
        old = case["observations"][provider]
        observations[provider] = replace(old, state_json=raw, classification=replace(old.classification,
            state_sha256=sha256(raw).hexdigest(), serial=json.loads(raw)["serial"]))
    args = {k: case[k] for k in ("append_parent", "host_proof_child", "host_receipt", "provider_children",
        "reviewed_chain_fingerprints", "chains", "live_bindings")}
    args["live_bindings"] = {k: tuple(v) for k, v in args["live_bindings"].items()}
    scope = build_mixed_published_six_teardown_scope(source, reviewed_policies=reopened.policies,
        observations=observations, current_generation=reopened, **args)
    assert tuple(s["stateSha256"] for s in scope.provider_scopes) == reopened.state_sha256s
