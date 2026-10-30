# Copyright (c) 2026, Oracle and/or its affiliates.
"""Persisted append publication to authenticated firewall-only channel advances."""
from dataclasses import asdict, replace
from hashlib import sha256
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.domain import JobEvent
from app.services import provider_keyed_channel_generation as generation
from app.services.provider_keyed_channel_apply import _digest, _topology, HOST_EVENT
from app.services.provider_keyed_ingress_route_ledger import KeyedRouteIntent, render_keyed_route_projection
from app.services.provider_keyed_initial_teardown import _state_resources
from app.services.provider_keyed_mixed_published_six_scope import build_mixed_published_six_teardown_scope
from app.services.provider_keyed_mixed_append_pair_plan_worker import _name
from app.storage.job_repository import SqlAlchemyJobRepository
from app.storage.job_repository import job_event_digest
import test_provider_keyed_mixed_published_six_integration as persisted


def _write(path, value):
    raw = value if type(value) is bytes else json.dumps(value, sort_keys=True).encode()
    path.write_bytes(raw)
    path.chmod(0o600)
    return sha256(raw).hexdigest()


def _public(provider, proto, port):
    if provider == "linode":
        return {"action": "ACCEPT", "protocol": proto.upper(), "label": f"allow-{proto}-{port}",
                "ports": str(port), "ipv4": ["0.0.0.0/0"], "ipv6": None, "description": ""}
    return {"action": "allow", "protocol": proto, "port_range": str(port), "source_addresses": ["0.0.0.0/0"],
            "source_droplet_ids": [], "source_kubernetes_ids": [], "source_load_balancer_uids": [], "source_tags": []}


@pytest.fixture
def case(client, tmp_path, monkeypatch):
    policy_case = persisted._policy_case
    def complete_policy():
        source, approved, initial, policies, files = policy_case()
        for provider, policy in policies.items():
            policy.update(provider_connection_id="cred", credential_secret_sha256="2" * 64,
                          credential_updated_at="2026-10-19T00:00:00Z")
        return source, approved, initial, policies, files
    monkeypatch.setattr(persisted, "_policy_case", complete_policy)
    original = persisted._states_and_children
    def enriched(source, options):
        observations, children, _, _ = original(source, options)
        for provider in source.provider_order:
            observed = observations[provider]
            state = json.loads(observed.state_json)
            state['check_results'] = [{'object_kind': 'var', 'config_addr': f'var.{name}', 'status': 'pass',
                'objects': [{'object_addr': f'var.{name}', 'status': 'pass'}]}
                for name in ('middle_count', 'edge_count_per_region')]
            firewall = _state_resources(state)[f"{provider}_firewall.firewall"]
            field = "inbound" if provider == "linode" else "inbound_rule"
            firewall[field] = [_public(provider, "tcp", p) for p in (80, 443, 2222)]
            firewall["outbound_policy" if provider == "linode" else "outbound_rule"] = "ACCEPT" if provider == "linode" else []
            firewall["linodes" if provider == "linode" else "droplet_ids"] = (
                [int(n.provider_instance_id) for n in source.host_rows if n.provider == provider]
                if provider == "linode" else None)
            raw = json.dumps(state, sort_keys=True).encode()
            digest = sha256(raw).hexdigest()
            observations[provider] = replace(observed, state_json=raw,
                classification=replace(observed.classification, state_sha256=digest))
            child = children[provider]
            events = list(child.events)
            events[8] = replace(events[8], data={**events[8].data, "stateSha256": digest})
            events[9] = replace(events[9], data={"proofJournalSha256": job_event_digest(events[:9])})
            children[provider] = replace(child, events=events)
        return (observations, children, tuple(observations[p].classification.state_sha256 for p in source.provider_order),
                tuple(job_event_digest(children[p].events) for p in source.provider_order))
    monkeypatch.setattr(persisted, "_states_and_children", enriched)
    result = persisted.persisted_six_case(client, tmp_path, monkeypatch)
    source = result["source"]
    with client.application.storage_context():
        jobs = SqlAlchemyJobRepository()
        initial = next(j for j in jobs.list_for_engagement(source.engagement_id)
                       if j.action == "provider_keyed_mixed_initial")
        for index, provider in enumerate(source.provider_order):
            _write(Path(source.workspace_paths[index]) / "terraform.tfstate", result["observations"][provider].state_json)
        result.update(jobs=jobs, initial=initial)
        yield result


def _reopen(case):
    return generation.read_channel_generation(case["source"], case["append_parent"], case["initial"], case["jobs"])


def _advance(case, *, number=1, prior=None, mutate=None, anchored=False, route_override=None, noop_metadata=False):
    source, jobs = case["source"], case["jobs"]
    prior = prior or _reopen(case)
    chain = source.chains[0]
    route = KeyedRouteIntent("channel", "udp", chain.nodes[2]["terraformAddress"],
                            chain.nodes[0]["terraformAddress"], 5353, 8004, ("0.0.0.0/0",))
    routes = route_override if route_override is not None else (route,)
    topology, providers = _topology(source)
    projection = render_keyed_route_projection(topology, providers, routes)
    job_id = f"job-channel-{number}"
    proof = {"path": str(Path(source.workspace_paths[0]) / f".barragan-channel-{job_id}-after.json"), "sha256": "a" * 64}
    host = JobEvent(1, "info", HOST_EVENT, {"sourceSha256": source.source_sha256, "hostProof": proof,
        "changed": True, "priorRoutesSha256": _digest([]), "routes": [asdict(r) for r in routes]})
    events = [host]
    artifacts = {}
    for index, provider in enumerate(source.provider_order):
        if anchored and prior.provider_routes[provider] == projection.provider_routes[provider]:
            continue
        root = Path(source.workspace_paths[index])
        prefix = root / f".barragan-ingress-{job_id}"
        before_raw = (root / "terraform.tfstate").read_bytes()
        after = json.loads(before_raw)
        after["serial"] += 1
        firewall = _state_resources(after)[f"{provider}_firewall.firewall"]
        field = "inbound" if provider == "linode" else "inbound_rule"
        public = {("tcp", p) for p in (80, 443, 2222)} | {(r.protocol, r.port) for r in projection.provider_routes[provider]}
        firewall[field] = [_public(provider, proto, port) for proto, port in sorted(public)]
        if noop_metadata:
            after['check_results'].reverse()
        if mutate: mutate(provider, after)
        route_only = ({(r.protocol, r.port) for r in prior.provider_routes[provider]}
                      == {(r.protocol, r.port) for r in projection.provider_routes[provider]})
        after_raw = before_raw if anchored and route_only and not noop_metadata else json.dumps(after, sort_keys=True).encode()
        variables = {**prior.policies[provider]["nonsecret_varfile"],
                     "allowed_tcp_ports": ["22", "80", "443", "2222"],
                     "allowed_udp_ports": [str(p) for proto, p in sorted(public) if proto == "udp"]}
        old_receipt = json.loads((root / _name(provider, "plan-receipt.json")).read_bytes())
        host_ports = {address: tuple(sorted({(r["proto"], r["port"]) for r in projection.host_policies[address]["sketch_firewall_v2_rules"]
                     if r["port"] not in {80, 443, 2222}})) for address in sorted(prior.policies[provider]["nodes"])}
        status = {"phase": "applied", "jobId": job_id, "provider": provider, "schema": "keyed-ingress-update-v1",
                  "connectionId": prior.policies[provider]["provider_connection_id"],
                  "sourceRevision": source.source_revisions[index], "sourceSha256": old_receipt["sourceSha256"],
                  "topologySha256": _digest(json.loads((root / ".barragan-topology.json").read_bytes())),
                  "lockfileSha256": sha256((root / ".terraform.lock.hcl").read_bytes()).hexdigest(),
                  "routeSha256": _digest({"prior": [vars(r) for r in prior.provider_routes[provider]],
                                         "next": [vars(r) for r in projection.provider_routes[provider]], "selected": "channel", "hosts": host_ports}),
                  "credentialSha256": prior.policies[provider]["credential_secret_sha256"],
                  "credentialUpdatedAt": prior.policies[provider]["credential_updated_at"],
                  "retainedInputSha256": sha256(prior.input_paths[provider].read_bytes()).hexdigest(),
                  "reviewedInputSha256": _digest(variables), "stateSha256": sha256(before_raw).hexdigest(),
                  "postStateSha256": sha256(after_raw).hexdigest()}
        if anchored:
            status.update(schema="keyed-ingress-update-v2", predecessorReceiptSha256=prior.receipt_heads[provider])
        from app.services.provider_keyed_ingress_update import _write_private_json
        _write_private_json(Path(f"{prefix}-status.json"), status)
        row = {"sourceSha256": source.source_sha256, "jobId": job_id, "provider": provider,
               "beforeStateSha256": sha256(before_raw).hexdigest(), "afterStateSha256": sha256(after_raw).hexdigest(),
               "receiptSha256": sha256(Path(f"{prefix}-status.json").read_bytes()).hexdigest(),
               "inputSha256": _write(Path(f"{prefix}-inputs.json"), variables), "hostProof": proof}
        if anchored:
            row['predecessorReceiptSha256'] = prior.receipt_heads[provider]
        _write(Path(f"{prefix}-before.tfstate"), before_raw)
        _write(Path(f"{prefix}-after.tfstate"), after_raw)
        _write(root / "terraform.tfstate", after_raw)
        events.append(JobEvent(len(events) + 1, "info", generation.EVENT, row))
        artifacts[provider] = dict(prefix=prefix, row=row, status=status, inputs=variables)
    # Provider applies can complete before a later proxy phase fails.
    job = replace(case["append_parent"], id=job_id, action="inbound_channel_apply", status="failed",
                  input={"engagementId": source.engagement_id, "channelId": "channel"}, events=events)
    jobs.save(job)
    return job, artifacts, routes


def test_persisted_append_channel_advance_reopens_even_when_proxy_job_failed(case, monkeypatch):
    source = case["source"]
    before = asdict(source)
    job, artifacts, routes = _advance(case)
    # Use the production ingress receipt writer, then the strict generation reader.
    for artifact in artifacts.values():
        path = Path(f"{artifact['prefix']}-status.json")
        assert path.stat().st_mode & 0o777 == 0o600
    _real_host_proof(case, job, routes, monkeypatch)
    reopened = _reopen(case)
    assert asdict(source) == before
    assert len(reopened.advances) == 2
    assert all(reopened.provider_routes.values())
    assert all(reopened.input_paths[p] == Path(f"{a['prefix']}-inputs.json") for p, a in artifacts.items())
    observations = {}
    for index, provider in enumerate(source.provider_order):
        old = case["observations"][provider]
        raw = (Path(source.workspace_paths[index]) / "terraform.tfstate").read_bytes()
        observations[provider] = replace(old, state_json=raw, classification=replace(old.classification,
            state_sha256=sha256(raw).hexdigest(), serial=json.loads(raw)["serial"]))
    args = {key: case[key] for key in ("append_parent", "host_proof_child", "host_receipt", "provider_children",
            "reviewed_chain_fingerprints", "chains", "live_bindings")}
    args["live_bindings"] = {key: tuple(rows) for key, rows in args["live_bindings"].items()}
    scope = build_mixed_published_six_teardown_scope(source, reviewed_policies=reopened.policies,
        observations=observations, current_generation=reopened, **args)
    assert len(scope.provider_scopes) == 2 and scope.binding_count == 4
    assert tuple(p["stateSha256"] for p in scope.provider_scopes) == reopened.state_sha256s


@pytest.mark.parametrize("drift", ["noncomputed_attr", "baseline", "public22", "extra_resource", "identity", "egress", "attachment", "lineage", "serial"])
def test_rehashed_state_changes_outside_exact_firewall_ingress_veto(case, monkeypatch, drift):
    monkeypatch.setattr(generation, "require_channel_host_proof", lambda *args: None)
    def change(provider, state):
        resources = _state_resources(state)
        firewall = resources[f"{provider}_firewall.firewall"]
        field = "inbound" if provider == "linode" else "inbound_rule"
        if drift == "noncomputed_attr": firewall["new_unknown_attribute"] = "unreviewed"
        elif drift == "baseline": firewall[field] = [r for r in firewall[field] if (r.get("port_range") or r.get("ports")) != "443"]
        elif drift == "public22": firewall[field].append(_public(provider, "tcp", 22))
        elif drift == "extra_resource": state["resources"].append(persisted._resource("local_file.unreviewed", {"id": "extra"}))
        elif drift == "identity": resources[next(a for a in resources if a.startswith(("linode_instance.", "digitalocean_droplet.")))]["id"] = "foreign"
        elif drift == "egress": firewall["outbound_policy" if provider == "linode" else "outbound_rule"] = "DROP" if provider == "linode" else [{"unreviewed": True}]
        elif drift == "attachment": firewall["linodes" if provider == "linode" else "droplet_ids"] = [999]
        elif drift == "lineage": state["lineage"] = "foreign"
        elif drift == "serial": state["serial"] -= 1
    _advance(case, mutate=change)
    with pytest.raises(ValueError):
        _reopen(case)


def _rehash_status(case, job, artifacts, provider, field, value):
    artifact = artifacts[provider]
    status = {**artifact["status"], field: value}
    digest = _write(Path(f"{artifact['prefix']}-status.json"), status)
    events = [replace(event, data={**event.data, "receiptSha256": digest})
              if event.message == generation.EVENT and event.data["provider"] == provider else event
              for event in job.events]
    return case["jobs"].save(replace(job, events=events))


@pytest.mark.parametrize("field", ["connectionId", "sourceRevision", "sourceSha256", "topologySha256", "lockfileSha256", "routeSha256", "credentialSha256", "credentialUpdatedAt", "retainedInputSha256", "reviewedInputSha256", "stateSha256", "postStateSha256", "phase"])
def test_rehashed_receipt_authority_drift_veto(case, monkeypatch, field):
    monkeypatch.setattr(generation, "require_channel_host_proof", lambda *args: None)
    job, artifacts, _ = _advance(case)
    _rehash_status(case, job, artifacts, case["source"].provider_order[0], field, "changed")
    with pytest.raises(ValueError, match="receipt differs"):
        _reopen(case)


@pytest.mark.parametrize("drift", ["host_source", "host_policy", "host_after", "fork", "disconnected", "current_state", "private_path", "marker", "inputs"])
def test_history_and_artifact_binding_drift_veto(case, monkeypatch, drift):
    monkeypatch.setattr(generation, "require_channel_host_proof", lambda *args: None)
    job, artifacts, _ = _advance(case)
    events = list(job.events)
    provider = case["source"].provider_order[0]
    root = Path(case["source"].workspace_paths[0])
    if drift == "host_source": events[0] = replace(events[0], data={**events[0].data, "sourceSha256": "f" * 64})
    elif drift == "host_policy":
        routes = json.loads(json.dumps(events[0].data["routes"]))
        routes[0]["external_port"] = 5355
        events[0] = replace(events[0], data={**events[0].data, "routes": routes})
    elif drift == "host_after": events = [replace(events[0], sequence=4), *events[1:]]
    elif drift == "fork": events.append(replace(events[1], sequence=4))
    elif drift == "disconnected": events[1] = replace(events[1], data={**events[1].data, "beforeStateSha256": "f" * 64})
    elif drift == "current_state":
        state = json.loads((root / "terraform.tfstate").read_bytes()); state["serial"] += 1
        _write(root / "terraform.tfstate", state)
    elif drift == "private_path": Path(f"{artifacts[provider]['prefix']}-before.tfstate").chmod(0o644)
    elif drift == "marker": _write(root / ".barragan-provider-keyed-state.json", {"unreviewed": True})
    else:
        artifact = artifacts[provider]
        variables = {**artifact["inputs"], "unreviewed": True}
        inputs_sha = _write(Path(f"{artifact['prefix']}-inputs.json"), variables)
        status = {**artifact["status"], "reviewedInputSha256": _digest(variables)}
        receipt_sha = _write(Path(f"{artifact['prefix']}-status.json"), status)
        events[1] = replace(events[1], data={**events[1].data, "inputSha256": inputs_sha, "receiptSha256": receipt_sha})
    case["jobs"].save(replace(job, events=events))
    with pytest.raises(ValueError):
        _reopen(case)


def _real_host_proof(case, job, routes, monkeypatch):
    """Real raw dataclasses and interpreter, with the existing synthetic baseline.

    This is offline replay coverage, not a live firewall capture assertion.
    Literal rule serialization is independently covered in interpreter tests.
    """
    import test_provider_keyed_host_policy_interpreter as fixtures
    source = case["source"]
    topology, providers = _topology(source)
    policies = render_keyed_route_projection(topology, providers, routes).host_policies
    captures = []
    from app.services.provider_keyed_mixed_append_pair_host_proof import six_host_known_hosts_path
    for index, chain in enumerate(source.chains):
        for host_index, node in enumerate(chain.nodes):
            known = six_host_known_hosts_path(source, index, host_index)
            known_sha = _write(known, b"private fixture known hosts")
            provider = node["provider"]
            captured, _, outputs = (fixtures._linode_fixture(monkeypatch) if provider == "linode" else fixtures._fixture(monkeypatch))
            raw = captured.raw if provider == "linode" else captured
            policy = policies[node["terraformAddress"]]
            predecessor = policy["sketch_firewall_v2_ssh_sources"][0].removesuffix("/32")
            outputs = {key: value.replace(fixtures.PREDECESSOR, predecessor) for key, value in outputs.items()}
            nft = json.loads(outputs["nft_ruleset"])
            for rule in policy["sketch_firewall_v2_rules"]:
                proto, port, source_ip = rule["proto"], rule["port"], rule["from_ip"]
                public = source_ip == "0.0.0.0/0"
                host = source_ip.removesuffix("/32")
                outputs["ufw_status_verbose"] += f"{port}/{proto} ALLOW IN {'Anywhere' if public else host}\n"
                outputs["ufw_user_rules"] += (f"\n### tuple ### allow {proto} {port} 0.0.0.0/0 any {host} in\n"
                    f"-A ufw-user-input -p {proto} --dport {port}" + ("" if public else f" -s {host}") + " -j ACCEPT\n")
                outputs["iptables_save"] = outputs["iptables_save"].replace("COMMIT\n", "-A ufw-user-input"
                    + ("" if public else f" -s {source_ip}") + f" -p {proto} -m {proto} --dport {port} -j ACCEPT\nCOMMIT\n")
                expr = [] if public else [{"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "saddr"}}, "right": host}}]
                expr += [{"match": {"op": "==", "left": {"payload": {"protocol": proto, "field": "dport"}}, "right": port}},
                         {"counter": {"packets": 0, "bytes": 0}}, {"accept": None}]
                nft["nftables"].append({"rule": {"family": "ip", "table": "filter", "chain": "ufw-user-input", "handle": port, "expr": expr}})
            outputs["nft_ruleset"] = json.dumps(nft)
            identity = replace(raw.identity, manifest_sha256=source.source_sha256, chain_id=chain.chain_id,
                terraform_address=node["terraformAddress"], provider_instance_id=node["providerInstanceId"],
                hostname=node["hostname"], public_ipv4=node["publicIp"], region=node["region"],
                core_known_hosts_sha256=source.core_known_hosts_sha256, sketch_known_hosts_sha256=known_sha)
            for name, value in outputs.items():
                raw = fixtures._replace_output(raw, name, value)
                raw = fixtures._replace_after_output(raw, name, value)
            raw = replace(raw, identity=identity,
                firewall_before=replace(raw.firewall_before, identity=identity),
                firewall_after=replace(raw.firewall_after, identity=identity),
                surface=replace(raw.surface, identity=identity, predecessor_ipv4=predecessor,
                    ssh_connection=(predecessor, 50000, node["publicIp"], 22)))
            if provider == "linode":
                linode_identity = replace(captured.identity, **{name: getattr(identity, name) for name in (
                    "manifest_sha256", "chain_id", "terraform_address", "provider_instance_id", "hostname", "public_ipv4", "region",
                    "core_known_hosts_sha256", "sketch_known_hosts_sha256")}, ssh_connection=raw.surface.ssh_connection)
                raw = replace(captured, identity=linode_identity, raw=raw)
            captures.append(asdict(raw))
    path = Path(source.workspace_paths[0]) / f".barragan-channel-{job.id}-after.json"
    proof = {"path": str(path), "sha256": _write(path, {"sourceSha256": source.source_sha256,
             "policySha256": _digest(policies), "captures": captures})}
    job = case["jobs"].save(replace(job, events=[replace(event, data={**event.data, "hostProof": proof}) for event in job.events]))
    return path, job


def test_persisted_generation_replays_actual_interpreter_raw_host_evidence(case, monkeypatch):
    job, _, routes = _advance(case)
    _real_host_proof(case, job, routes, monkeypatch)
    reopened = _reopen(case)
    assert len(reopened.advances) == 2


@pytest.mark.parametrize("drift", ["source", "policy", "chain", "raw", "outside"])
def test_real_host_proof_binding_or_raw_policy_drift_veto(case, monkeypatch, drift):
    job, _, routes = _advance(case)
    path, job = _real_host_proof(case, job, routes, monkeypatch)
    document = json.loads(path.read_bytes())
    if drift == "source": document["sourceSha256"] = "f" * 64
    elif drift == "policy": document["policySha256"] = "f" * 64
    elif drift == "chain": document["captures"][0]["identity"]["chain_id"] = "foreign"
    elif drift == "raw":
        raw = document["captures"][0].get("raw", document["captures"][0])
        raw["firewall_after"]["commands"][0]["raw_output"] += "unreviewed"
    else: path = path.parent.parent / path.name
    proof = {"path": str(path), "sha256": _write(path, document)}
    case["jobs"].save(replace(job, events=[replace(event, data={**event.data, "hostProof": proof}) for event in job.events]))
    with pytest.raises(ValueError):
        _reopen(case)


def test_provider_reader_receipt_heads_disambiguate_cycles_without_enabling_host_cycles(case, monkeypatch):
    from app.services.provider_keyed_channel_apply import _prior_host_routes
    source = case['source']
    a, b = source.chains
    first_edge, second_edge = a.nodes[2], b.nodes[1]
    assert first_edge['provider'] == second_edge['provider']
    fixed = (KeyedRouteIntent('seed-a', 'udp', second_edge['terraformAddress'], b.nodes[0]['terraformAddress'],
                            5353, 8005, ('0.0.0.0/0',)),
             KeyedRouteIntent('seed-b', 'udp', second_edge['terraformAddress'], b.nodes[0]['terraformAddress'],
                            5354, 8006, ('0.0.0.0/0',)))
    prior_routes = ()
    prior = _reopen(case)
    for number, port in enumerate((5353, 5354, 5353, 5354), 1):
        selected = KeyedRouteIntent('channel', 'udp', first_edge['terraformAddress'], a.nodes[0]['terraformAddress'],
                                   port, 8004, ('0.0.0.0/0',))
        routes = tuple(sorted((*fixed, selected), key=lambda r: r.channel_id))
        job, artifacts, _ = _advance(case, number=number, prior=prior, anchored=number > 1, route_override=routes)
        job = replace(job, events=[replace(e, data={**e.data, 'priorRoutesSha256': _digest([asdict(r) for r in prior_routes])})
                                  if e.message == HOST_EVENT else e for e in job.events])
        case['jobs'].save(job)
        _real_host_proof(case, job, routes, monkeypatch)
        reopened = _reopen(case)
        if number > 1:
            assert len(artifacts) == 1
            artifact = next(iter(artifacts.values()))
            assert artifact['row']['beforeStateSha256'] == artifact['row']['afterStateSha256']
        prior, prior_routes = reopened, routes
    assert len(prior.advances) == 5
    # Existing operator host-ledger cycles remain fail-closed; this is only
    # provider-reader ordering, not support for re-editing an operator route cycle.
    with pytest.raises(ValueError, match='forked'):
        _prior_host_routes(source, case['jobs'])


@pytest.mark.parametrize('drift', [None, 'outputs', 'private', 'check_status', 'nested_order', 'serial_jump'])
def test_authenticated_history_rechecks_noop_metadata_not_just_receipt_hashes(case, monkeypatch, drift):
    from copy import deepcopy
    source = case['source']
    a, b = source.chains
    first, second = a.nodes[2], b.nodes[1]
    fixed = (KeyedRouteIntent('seed-a', 'udp', second['terraformAddress'], b.nodes[0]['terraformAddress'],
                             5353, 8005, ('0.0.0.0/0',)),
             KeyedRouteIntent('seed-b', 'udp', second['terraformAddress'], b.nodes[0]['terraformAddress'],
                             5354, 8006, ('0.0.0.0/0',)))
    selected = KeyedRouteIntent('channel', 'udp', first['terraformAddress'], a.nodes[0]['terraformAddress'],
                               5353, 8004, ('0.0.0.0/0',))
    job, _, routes = _advance(case, route_override=(*fixed, selected))
    _real_host_proof(case, job, routes, monkeypatch)
    prior = _reopen(case)
    def change(_provider, state):
        if drift == 'outputs': state.setdefault('outputs', {})['alien'] = {'value': 'changed'}
        elif drift == 'private': state['resources'][0]['instances'][0]['private'] = 'changed'
        elif drift == 'check_status': state['check_results'][0]['status'] = 'unknown'
        elif drift == 'nested_order':
            # A changed nested object order/content is never top-level row reordering.
            state['check_results'][0]['objects'].append(deepcopy(state['check_results'][1]['objects'][0]))
        elif drift == 'serial_jump': state['serial'] += 1
    job, _, routes = _advance(case, number=2, prior=prior, anchored=True, noop_metadata=True,
        route_override=(*fixed, replace(selected, external_port=5354)), mutate=change)
    _real_host_proof(case, job, routes, monkeypatch)
    # _advance hashes the actual altered state into both private status and SQL
    # journal; negatives therefore reach semantic history validation.
    if drift is None:
        assert len(_reopen(case).advances) == 3
    else:
        with pytest.raises(ValueError): _reopen(case)
