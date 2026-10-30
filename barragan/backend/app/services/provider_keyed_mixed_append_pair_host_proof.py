# Copyright (c) 2026, Oracle and/or its affiliates.
"""Private, one-shot routed host proof for the paired mixed-provider append.

The new edge in each chain lives on the *other* provider.  Existing provider
collectors assume a same-provider middle, so their manifest adapters cannot be
used here.  This module binds the six-node source, then uses their lower-level
SSH capture and strict policy interpreters without inventing a local middle.
The caller supplies a fresh, authenticated state/provider reopener; this module
never grants Apply authority or publishes chain rows.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
from typing import Callable, Mapping
from uuid import uuid4

from app.core.command_environment import barragan_subprocess_env
from app.services.bootstrap_command_evidence import bootstrap_command_timing, without_bootstrap_timing
from app.domain import JobEvent
from app.services.provider_keyed_gated_runner import (
    CommandResult, GatedCommandTimeoutError, UnreapedGatedCommandError, _private_scratch_path,
    run_gated_command,
)
from app.services.provider_keyed_host_binding import _regular_file_digest
from app.services.provider_keyed_host_identity_probe import (
    DigitalOceanHostIdentityEvidence, DigitalOceanRawHostCollection,
    _collect_raw_firewall, _collect_raw_host_surface, _quoted_remote_script,
    _require_pinned_aliases, _stable_firewall_commands,
)
from app.services.provider_keyed_host_policy_interpreter import (
    interpret_digitalocean_host_policy, interpret_linode_host_policy,
)
from app.services.provider_keyed_host_surface_interpreter import (
    _key_digest, interpret_digitalocean_host_surface, interpret_linode_host_surface,
)
from app.services.provider_keyed_initial_bootstrap import _sketch_file_snapshot
from app.services.provider_keyed_initial_bootstrap import _clean_scratch_result
from app.services.provider_keyed_host_policy import Edge, Middle, Topology, render_sketch_host_policy
from app.services.provider_keyed_append_host_collection import _decode_type
from app.services.provider_keyed_mixed_initial_publication_source import MixedHostRow
from app.services.provider_keyed_mixed_strict_host_receipt import _read_private_evidence
from app.services.provider_keyed_mixed_linode_host_probe import (
    LinodeRawHostCollection, LinodeRawHostIdentity, _parse_identity,
    _sudo_hostname_warning, _SCRIPT as _LINODE_METADATA_SCRIPT,
)
from app.services.provider_keyed_runtime_preflight import _db_lease_lookup
from app.services.redteam_infra_template import TEMPLATE_ROOT_ENV
from app.services.sketch_bootstrap import (
    SketchBootstrapSpec, render_strict_v2_sketch_identity_ssh_config,
)
from app.services.sketch_bootstrap_apply import (
    SketchBootstrapApplyResult, _core_hosts, _sketch_nodes,
    BOOTSTRAP_COMMAND_TIMEOUT_SECONDS, BOOTSTRAP_TIMEOUT_MESSAGE, SketchBootstrapTimeoutError,
    apply_sketch_bootstrap, require_pinned_sketch_ansible_source,
)
from app.services.sketch_ssh_keys import (
    retrieve_sketch_ssh_key, write_existing_sketch_ssh_key_files,
)
from app.services.sketch_transport_ssh_keys import retrieve_sketch_transport_ssh_key
from app.storage.job_repository import SqlAlchemyJobRepository, StoredJobRun, job_event_digest
from app.storage.sketch_chain_repository import StoredSketchChain


ACTION = "provider_keyed_mixed_append_pair_host_proof"
_OPERATION = "provider_keyed_mixed_append"
_OWNER_PREFIX = "mixed-append-host-proof-"
_PROVIDERS = frozenset({"digitalocean", "linode"})
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_PHASES = (
    ("readiness", "wait_for_sketch_readiness.yml"),
    ("root", "upstream-sketch-playbook.compat.yml"),
    ("user_readiness", "wait_for_sketch_user_readiness.yml"),
    ("transport", "install_sketch_transport.yml"),
)


class MixedAppendPairHostProofAttention(ValueError):
    """A routed host contact is absent or uncertain and must not be replayed."""


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


@dataclass(frozen=True)
class SixNodeHostSource:
    parent_id: str
    engagement_id: str
    core_job_id: str
    core_plan_id: str
    provider_order: tuple[str, str]
    chain_ids: tuple[str, str]
    before_chains: tuple[StoredSketchChain, StoredSketchChain]
    chains: tuple[StoredSketchChain, StoredSketchChain]
    new_edge_addresses: tuple[str, str]
    provider_proof_digests: tuple[str, str]
    state_sha256s: tuple[str, str]
    workspace_paths: tuple[str, str]
    source_revisions: tuple[str, str]
    proxy_egress_ips: tuple[str, str]
    core_known_hosts_path: str
    core_known_hosts_sha256: str

    @property
    def source_sha256(self) -> str:
        return _sha(asdict(self))

    @property
    def host_rows(self) -> tuple[MixedHostRow, ...]:
        return tuple(MixedHostRow(
            chain.chain_id, node["provider"], node["role"], node["hostname"],
            node["terraformAddress"], node["providerInstanceId"],
            node["publicIp"], chain.assigned_proxy,
        ) for chain in self.chains for node in chain.nodes)


@dataclass(frozen=True)
class SixHostProofReceipt:
    parent_id: str
    child_id: str
    source_sha256: str
    provider_order: tuple[str, str]
    chain_ids: tuple[str, str]
    new_edge_addresses: tuple[str, str]
    new_edge_ids: tuple[str, str]
    provider_proof_digests: tuple[str, str]
    bootstrap_event_sha256s: tuple[str, str]
    sketch_known_hosts_sha256s: tuple[str, str]
    raw_probe_sha256s: tuple[str, str]
    child_event_sha256: str
    claim_owner: str
    claim_token: str


def _child_id(parent_id: str) -> str:
    if not parent_id.startswith("job-provider-keyed-mixed-append-"):
        raise ValueError("mixed append parent ID differs")
    return f"job-provider-keyed-mixed-append-host-proof-{parent_id.removeprefix('job-provider-keyed-mixed-append-')}"


def validate_six_node_host_source(source: SixNodeHostSource) -> SixNodeHostSource:
    """Bind two original 2-node chains to two 3-node cross-provider projections."""
    try:
        if (type(source) is not SixNodeHostSource
                or source.parent_id != f"job-provider-keyed-mixed-append-{source.core_job_id.removeprefix('job-')}"
                or any(type(value) is not str or not value for value in (
                    source.engagement_id, source.core_job_id, source.core_plan_id,
                    source.core_known_hosts_path))
                or type(source.provider_order) is not tuple
                or len(source.provider_order) != 2 or set(source.provider_order) != _PROVIDERS
                or type(source.chain_ids) is not tuple or len(source.chain_ids) != 2
                or len(set(source.chain_ids)) != 2
                or any(type(rows) is not tuple or len(rows) != 2 for rows in (
                    source.before_chains, source.chains))
                or any(type(rows) is not tuple or len(rows) != 2 or
                       any(type(value) is not str or not value for value in rows)
                       for rows in (source.new_edge_addresses,
                                    source.provider_proof_digests,
                                    source.state_sha256s, source.workspace_paths,
                                    source.source_revisions,
                                    source.proxy_egress_ips))
                or any(_HASH.fullmatch(value) is None for value in (
                    *source.provider_proof_digests, *source.state_sha256s,
                    source.core_known_hosts_sha256))):
            raise ValueError("six-node source envelope differs")
        seen_addresses, seen_hostnames, seen_ips = set(), set(), set()
        for index, provider in enumerate(source.provider_order):
            before, after = source.before_chains[index], source.chains[index]
            if (type(before) is not StoredSketchChain or type(after) is not StoredSketchChain
                    or before.chain_id != source.chain_ids[index]
                    or after.chain_id != before.chain_id
                    or before.engagement_id != source.engagement_id
                    or after.engagement_id != source.engagement_id
                    or after.assigned_proxy != before.assigned_proxy
                    or after.middle_provider != before.middle_provider
                    or after.edge_provider != before.edge_provider
                    or before.middle_provider == provider
                    or before.edge_provider != before.middle_provider
                    or before.status != "deployed" or after.status != "deployed"
                    or before.burned or after.burned
                    or len(before.nodes) != 2 or len(after.nodes) != 3
                    or after.nodes[0] != before.nodes[0]
                    or after.nodes[1] != {**before.nodes[1], "edgeCount": "2"}
                    or [row.get("role") for row in after.nodes]
                       != ["middle", "edge", "edge"]
                    or [row.get("provider") for row in after.nodes]
                       != [before.middle_provider, before.middle_provider, provider]
                    or after.nodes[2].get("terraformAddress")
                       != source.new_edge_addresses[index]
                    or after.nodes[2].get("chainId") != after.chain_id
                    or any(row.get("assignedProxy") != after.assigned_proxy
                           for row in after.nodes)
                    or after.terraform_working_directory
                       != before.terraform_working_directory
                    or not Path(source.workspace_paths[index]).is_absolute()
                    or not Path(source.core_known_hosts_path).is_absolute()
                    or not source.proxy_egress_ips[index]):
                raise ValueError("six-node cross-provider topology differs")
            for row in after.nodes:
                address, name, ip = (row.get(key) for key in (
                    "terraformAddress", "hostname", "publicIp"))
                if (type(address) is not str or type(name) is not str
                        or type(ip) is not str or not address or not name
                        or str(ipaddress.IPv4Address(ip)) != ip
                        or not ipaddress.IPv4Address(ip).is_global
                        or address in seen_addresses or name in seen_hostnames
                        or ip in seen_ips):
                    raise ValueError("six-node host identity collides")
                seen_addresses.add(address)
                seen_hostnames.add(name)
                seen_ips.add(ip)
        if len(source.host_rows) != 6:
            raise ValueError("six-node host set is incomplete")
        return source
    except (ValueError, TypeError, AttributeError, KeyError) as exc:
        raise MixedAppendPairHostProofAttention("joined six-node host source differs") from exc


def six_host_known_hosts_path(source: SixNodeHostSource, chain_index: int, host_index: int) -> Path:
    """Use native retained trust for old hosts and append trust for new edges."""
    if (type(chain_index) is not int or chain_index not in (0, 1)
            or type(host_index) is not int or host_index not in (0, 1, 2)):
        raise MixedAppendPairHostProofAttention("host trust index differs")
    index = (chain_index if host_index == 2 else
             source.provider_order.index(source.chains[chain_index].middle_provider))
    return Path(source.workspace_paths[index]) / ".barragan-sketch-known-hosts"


def _probe_cross_provider_edge(
    source: SixNodeHostSource, index: int, spec: SketchBootstrapSpec, *,
    scratch: Path, sketch_known_hosts_sha256: str,
    fence: Callable[[], None],
    on_scratch: Callable[[str], None], on_intent: Callable,
    on_started: Callable, on_heartbeat: Callable, on_result: Callable,
    runner: Callable = run_gated_command,
    host_index: int = 2, expected_policy: dict | None = None,
) -> DigitalOceanRawHostCollection | LinodeRawHostCollection:
    """Capture a selected host over its pinned homebase/proxy management route.

    The default foreign-edge mode retains its full append surface proof. The
    optional reviewed-policy mode reuses metadata and before/surface/after
    collection for firewall proof on any of the six published hosts.
    """
    validate_six_node_host_source(source)
    trust_path = six_host_known_hosts_path(source, index, host_index)
    chain = source.chains[index]
    node, middle = chain.nodes[host_index], chain.nodes[0]
    provider = node["provider"]
    predecessor = source.proxy_egress_ips[index] if host_index == 0 else middle["publicIp"]
    if (spec.middle.name != middle["hostname"]
            or spec.middle.public_ip != middle["publicIp"]
            or len(spec.edges) != 2
            or [(edge.name, edge.public_ip) for edge in spec.edges] != [
                (row["hostname"], row["publicIp"]) for row in chain.nodes[1:]]
            or spec.homebase.host == node["publicIp"]
            or spec.proxy.host_key_alias != source.proxy_egress_ips[index]
            or spec.proxy_egress_ip != source.proxy_egress_ips[index]
            or spec.proxy.ssh_private_key_path != spec.homebase.ssh_private_key_path
            or spec.pinned_core_known_hosts_path != source.core_known_hosts_path
            or spec.initial_sketch_known_hosts_path != str(trust_path)):
        raise MixedAppendPairHostProofAttention("foreign-edge operator route differs")
    policy = expected_policy if expected_policy is not None else {
        "sketch_firewall_v2_enabled": True,
        "sketch_firewall_v2_ssh_sources": [predecessor + "/32"],
        "sketch_firewall_v2_rules": [],
    }
    if policy.get("sketch_firewall_v2_ssh_sources") != [predecessor + "/32"]:
        raise MixedAppendPairHostProofAttention("host predecessor differs")
    if spec.host_policies.get(node["hostname"]) != policy:
        raise MixedAppendPairHostProofAttention("foreign-edge host policy differs")
    core = Path(source.core_known_hosts_path)
    sketch = Path(spec.initial_sketch_known_hosts_path)
    if (core == sketch or not scratch.is_absolute() or scratch.exists()
            or scratch.is_symlink() or sketch.is_symlink() or core.is_symlink()):
        raise MixedAppendPairHostProofAttention("foreign-edge scratch or trust path differs")
    executable = Path("/usr/bin/ssh")
    if (not executable.is_file() or executable.is_symlink()
            or executable.resolve(strict=True) != executable
            or not os.access(executable, os.X_OK)):
        raise MixedAppendPairHostProofAttention("strict SSH executable differs")
    scratch.mkdir(mode=0o700)
    scratch.chmod(0o700)
    _private_scratch_path(scratch)
    config_path = key_dir = None
    uncertain = False
    try:
        fence()
        core_digest = _regular_file_digest(core, require_content=True)
        sketch_before = _sketch_file_snapshot(sketch)
        if (core_digest != source.core_known_hosts_sha256
                or sketch_before[2] != sketch_known_hosts_sha256):
            raise ValueError("retained host trust changed")
        _require_pinned_aliases(core, (spec.homebase.host, spec.proxy.host_key_alias))
        _require_pinned_aliases(sketch, (
            f"barragan-bootstrap-sketch-{spec.middle.name}",
            f"barragan-bootstrap-sketch-{node['hostname']}",
        ))
        on_scratch(str(scratch))
        fence()
        key_dir = scratch / "keys"
        private, _ = write_existing_sketch_ssh_key_files(source.engagement_id, key_dir)
        private = Path(private)
        key_stat, private_stat = key_dir.lstat(), private.lstat()
        if (not stat.S_ISDIR(key_stat.st_mode) or key_stat.st_uid != os.getuid()
                or stat.S_IMODE(key_stat.st_mode) != 0o700
                or not stat.S_ISREG(private_stat.st_mode)
                or private_stat.st_uid != os.getuid() or private_stat.st_nlink != 1
                or stat.S_IMODE(private_stat.st_mode) != 0o600):
            raise ValueError("staged sketch administration key is unsafe")
        config = render_strict_v2_sketch_identity_ssh_config(
            replace(spec, admin_private_key_path=str(private)))
        alias = f"barragan-bootstrap-user-{node['hostname']}"
        if (f"Host {alias}\n" not in config
                or config.count("  ConnectTimeout 15") != config.count("Host ")
                or "StrictHostKeyChecking accept-new" in config
                or "ControlMaster no" not in config or "ControlPersist no" not in config):
            raise ValueError("strict foreign-edge SSH route differs")
        config = config.replace("  ConnectTimeout 15",
                                "  ConnectTimeout 15\n  ServerAliveInterval 10\n  ServerAliveCountMax 3")
        config_path = scratch / "identity-ssh.conf"
        fd = os.open(config_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            payload = config.encode()
            if os.write(fd, payload) != len(payload):
                raise OSError("strict SSH config write incomplete")
            os.fsync(fd)
        finally:
            os.close(fd)
        metadata_script = (_LINODE_METADATA_SCRIPT if provider == "linode"
                           else _quoted_remote_script())
        command = [str(executable), "-F", str(config_path), alias,
                   "python3", "-c", shlex.quote(metadata_script)
                   if provider == "linode" else metadata_script]
        intent = started = result = None

        def intent_cb(value):
            nonlocal intent
            fence()
            if intent is not None or value.scratch_path != str(scratch):
                raise ValueError("foreign-edge metadata intent differs")
            on_intent(value)
            intent = value

        def started_cb(value):
            nonlocal started
            fence()
            if intent is None or started is not None or value.intent != intent:
                raise ValueError("foreign-edge metadata start differs")
            on_started(value)
            started = value

        def result_cb(value):
            nonlocal result
            fence()
            if started is None or result is not None or value.started != started:
                raise ValueError("foreign-edge metadata result differs")
            on_result(value)
            result = value

        def heartbeat_cb(value):
            fence()
            if value != started or result is not None:
                raise ValueError("foreign-edge metadata heartbeat differs")
            on_heartbeat(value)

        outcome = runner(command, scratch_path=scratch, provider_keyed_v2=True,
                         env=barragan_subprocess_env(), intent_callback=intent_cb,
                         started_callback=started_cb,
                         heartbeat_callback=heartbeat_cb,
                         result_callback=result_cb)
        fence()
        if (not isinstance(outcome, CommandResult) or intent is None
                or started is None or result is None or outcome.started != started
                or outcome.returncode != 0 or result.returncode != 0
                or outcome.stdout_truncated or outcome.stderr_truncated
                or len(outcome.stdout.encode()) > 8192
                or _regular_file_digest(core, require_content=True) != core_digest
                or _sketch_file_snapshot(sketch) != sketch_before):
            raise ValueError("foreign-edge metadata observation incomplete")
        if provider == "linode":
            if outcome.stderr:
                raise ValueError("Linode metadata stderr differs")
            boot, connection = _parse_identity(
                outcome.stdout, expected=node, image="linode/ubuntu24.04",
                predecessor=predecessor)
        else:
            data = json.loads(outcome.stdout)
            if (type(data) is not dict
                    or set(data) != {"id", "region", "public_ipv4", "hostname", "boot_id"}
                    or any(type(value) is not str or not value for value in data.values())
                    or (data["id"], data["region"], data["public_ipv4"],
                        data["hostname"]) != (
                        node["providerInstanceId"], node["region"],
                        node["publicIp"], node["hostname"])):
                raise ValueError("DigitalOcean metadata differs")
            from uuid import UUID
            boot = str(UUID(data["boot_id"]))
            if boot != data["boot_id"].lower():
                raise ValueError("DigitalOcean boot identity differs")
        identity = DigitalOceanHostIdentityEvidence(
            source.source_sha256, chain.chain_id, node["terraformAddress"],
            node["providerInstanceId"], node["region"], node["publicIp"],
            node["hostname"], boot, alias, intent.invocation_id,
            core_digest, sketch_before[2])
        kwargs = {"expected_stderr": _sudo_hostname_warning(node["hostname"])} if provider == "linode" else {}
        common = (identity, executable, config_path, alias, scratch, core,
                  core_digest, sketch, sketch_before, fence, on_intent,
                  on_started, on_heartbeat, on_result, runner)
        before = _collect_raw_firewall(*common, **kwargs)
        surface = _collect_raw_host_surface(
            identity, predecessor, *common[1:], **kwargs)
        after = _collect_raw_firewall(*common, **kwargs)
        if (before.boot_id != boot or surface.boot_id != boot or after.boot_id != boot
                or before.completed_at_ns > surface.started_at_ns
                or surface.completed_at_ns > after.started_at_ns
                or after.completed_at_ns - before.started_at_ns > 300_000_000_000
                or _stable_firewall_commands(before.commands)
                   != _stable_firewall_commands(after.commands)
                or [(row.name, row.status, row.sha256, row.byte_count,
                     row.uid, row.gid, row.mode) for row in before.files]
                   != [(row.name, row.status, row.sha256, row.byte_count,
                        row.uid, row.gid, row.mode) for row in after.files]):
            raise ValueError("foreign-edge host policy changed during capture")
        raw = DigitalOceanRawHostCollection(identity, before, surface, after)
        if provider == "linode":
            linode_identity = LinodeRawHostIdentity(
                source.source_sha256, chain.chain_id, node["terraformAddress"],
                node["providerInstanceId"], "linode/ubuntu24.04",
                node["region"], node["publicIp"], node["hostname"], boot,
                connection, intent.invocation_id, core_digest, sketch_before[2])
            captured = LinodeRawHostCollection(linode_identity, raw)
        else:
            captured = raw
        if expected_policy is None and host_index == 2:
            _write_socket_diagnostic(source, index, _child_id(source.parent_id), captured)
            _verify_cross_provider_collection(
                source, index, captured,
                sketch_known_hosts_sha256=sketch_known_hosts_sha256)
        else:
            interpreter = (interpret_linode_host_policy if provider == "linode"
                           else interpret_digitalocean_host_policy)
            interpreter(captured, expected_identity=captured.identity,
                        expected_predecessor_ipv4=predecessor,
                        expected_policy=policy)
        return captured
    except UnreapedGatedCommandError:
        uncertain = True
        raise
    finally:
        if not uncertain:
            if config_path is not None and config_path.exists():
                if config_path.is_symlink():
                    raise MixedAppendPairHostProofAttention("probe SSH config cleanup unproved")
                config_path.unlink()
            if key_dir is not None and key_dir.exists():
                if key_dir.is_symlink():
                    raise MixedAppendPairHostProofAttention("probe key cleanup unproved")
                shutil.rmtree(key_dir)
            if scratch.exists() and not any(scratch.iterdir()):
                scratch.rmdir()


def _verify_cross_provider_collection(source: SixNodeHostSource, index: int,
                                      captured: object, *,
                                      sketch_known_hosts_sha256: str) -> str:
    provider, chain = source.provider_order[index], source.chains[index]
    node, middle = chain.nodes[2], chain.nodes[0]
    identity = captured.identity
    if (identity.manifest_sha256 != source.source_sha256
            or identity.chain_id != chain.chain_id
            or identity.terraform_address != node["terraformAddress"]
            or identity.provider_instance_id != node["providerInstanceId"]
            or identity.region != node["region"]
            or identity.public_ipv4 != node["publicIp"]
            or identity.hostname != node["hostname"]
            or identity.core_known_hosts_sha256 != source.core_known_hosts_sha256
            or identity.sketch_known_hosts_sha256 != sketch_known_hosts_sha256):
        raise ValueError("foreign-edge raw identity differs")
    policy = {"sketch_firewall_v2_enabled": True,
              "sketch_firewall_v2_ssh_sources": [middle["publicIp"] + "/32"],
              "sketch_firewall_v2_rules": []}
    admin = retrieve_sketch_ssh_key(source.engagement_id)
    transport = retrieve_sketch_transport_ssh_key(source.engagement_id)
    if admin is None or transport is None:
        raise ValueError("retained Sketch keys unavailable")
    admin_sha = _key_digest(admin.public_key.strip() + "\n")
    transport_sha = _key_digest(transport.public_key.strip() + "\n")
    if provider == "linode":
        firewall = interpret_linode_host_policy(
            captured, expected_identity=identity,
            expected_predecessor_ipv4=middle["publicIp"], expected_policy=policy)
        surface = interpret_linode_host_surface(
            captured, expected_identity=identity,
            expected_predecessor_ipv4=middle["publicIp"], expected_role="edge",
            expected_admin_key_sha256=admin_sha,
            expected_transport_key_sha256=transport_sha, expected_policy=policy)
        raw = captured.raw
    else:
        firewall = interpret_digitalocean_host_policy(
            captured, expected_identity=identity,
            expected_predecessor_ipv4=middle["publicIp"], expected_policy=policy)
        surface = interpret_digitalocean_host_surface(
            captured, expected_identity=identity,
            expected_predecessor_ipv4=middle["publicIp"], expected_role="edge",
            expected_admin_key_sha256=admin_sha,
            expected_transport_key_sha256=transport_sha, expected_policy=policy)
        raw = captured
    invocations = (identity.invocation_id, raw.firewall_before.invocation_id,
                   raw.surface.invocation_id, raw.firewall_after.invocation_id)
    if (firewall.predecessor_ipv4 != middle["publicIp"]
            or surface.complete_ssh_policy is not True
            or len(set(invocations)) != 4):
        raise ValueError("foreign-edge strict SSH/firewall proof incomplete")
    return _sha(asdict(captured))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _later(at: str) -> str:
    return (datetime.fromisoformat(at) + timedelta(seconds=3600)).isoformat()


def _artifact_path(source: SixNodeHostSource, index: int, child_id: str) -> Path:
    return Path(source.workspace_paths[index]) / (
        f".barragan-mixed-append-host-proof-{child_id}-{source.provider_order[index]}.json")


def _write_private(path: Path, payload: bytes) -> None:
    if not payload or len(payload) > 5_000_000:
        raise ValueError("foreign-edge raw artifact exceeds bound")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                 getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        view = memoryview(payload)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("foreign-edge raw artifact write incomplete")
            view = view[count:]
        os.fsync(fd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("foreign-edge raw artifact is unsafe")
    finally:
        os.close(fd)



def _write_socket_diagnostic(source: SixNodeHostSource, index: int,
                             child_id: str, collection: object) -> None:
    """Private observation only; never read as a proof/receipt artifact."""
    if (type(child_id) is not str or not re.fullmatch(r"[A-Za-z0-9_-]{1,200}", child_id)
            or child_id != _child_id(source.parent_id)):
        raise ValueError("socket diagnostic child differs")
    raw = collection.raw if source.provider_order[index] == "linode" else collection
    listeners = raw.surface.listeners_raw
    if (type(listeners) is not str or not listeners
            or len(listeners.encode("utf-8")) > 65536):
        raise ValueError("socket diagnostic exceeds bound")
    payload = json.dumps({
        "schema": "mixed-append-socket-diagnostic-v1", "authority": False,
        "sourceSha256": source.source_sha256, "childId": child_id,
        "provider": source.provider_order[index],
        "edgeAddress": source.new_edge_addresses[index],
        "metadataInvocationId": raw.identity.invocation_id,
        "surfaceInvocationId": raw.surface.invocation_id,
        "bootId": raw.surface.boot_id,
        "listenersSha256": hashlib.sha256(listeners.encode("utf-8")).hexdigest(),
        "listenersRaw": listeners,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > 400000:
        raise ValueError("socket diagnostic envelope exceeds bound")
    path = Path(source.workspace_paths[index]) / (
        f".barragan-mixed-append-socket-diagnostic-{child_id}-{source.provider_order[index]}.json")
    _write_private(path, payload)


def _read_collection(source: SixNodeHostSource, index: int, child_id: str,
                     expected_sha: str, sketch_known_hosts_sha256: str):
    path = _artifact_path(source, index, child_id)
    raw = _read_private_evidence(path, expected_sha)
    kind = (LinodeRawHostCollection if source.provider_order[index] == "linode"
            else DigitalOceanRawHostCollection)
    collection = _decode_type(kind, json.loads(raw))
    if _sha(asdict(collection)) != expected_sha:
        raise ValueError("foreign-edge raw artifact round trip differs")
    _verify_cross_provider_collection(
        source, index, collection,
        sketch_known_hosts_sha256=sketch_known_hosts_sha256)
    return collection


def _host_policy(source: SixNodeHostSource, index: int) -> dict:
    chain = source.chains[index]
    middle = chain.nodes[0]
    return render_sketch_host_policy(Topology(
        proxy_egress_ips={chain.assigned_proxy: source.proxy_egress_ips[index]},
        middles={middle["hostname"]: Middle(middle["publicIp"], chain.assigned_proxy)},
        edges={row["hostname"]: Edge(row["publicIp"], middle["hostname"])
               for row in chain.nodes[1:]},
    ), ())


def _bootstrap_edge(
    source: SixNodeHostSource, index: int, *, jobs, bootstrap_env,
    fence: Callable[[], None], record: Callable[[str, dict], None],
    bootstrap_helper: Callable, gated_command_runner: Callable,
) -> str:
    provider, chain = source.provider_order[index], source.chains[index]
    edge = chain.nodes[2]
    workspace = Path(source.workspace_paths[index])
    scratch = workspace / f".barragan-mixed-append-bootstrap-{uuid4().hex}"
    completed: list[str] = []
    attempts: dict[str, int] = {}
    first_contact = False
    record("mixed append edge bootstrap intended", {
        "provider": provider, "chainId": chain.chain_id,
        "edgeAddress": edge["terraformAddress"]})

    def reporter(status: str, data: dict) -> None:
        nonlocal first_contact
        fence()
        if (status == "checking" and data.get("phase") == "root-management-readiness"
                and not first_contact):
            record("mixed append edge first contact fenced", {"provider": provider})
            first_contact = True

    def command_runner(command: list[str], cwd: Path | None,
                       command_env: Mapping[str, str]):
        if cwd != scratch:
            raise ValueError("foreign-edge bootstrap scratch differs")
        matches = [name for name, path in _PHASES
                   if any(str(value).endswith(path) for value in command)]
        if len(matches) != 1 or matches[0] != _PHASES[len(completed)][0]:
            raise ValueError("foreign-edge bootstrap command order differs")
        phase = matches[0]
        attempts[phase] = attempts.get(phase, 0) + 1
        invocation = {"intent": None, "started": None, "result": None}
        fields = {"provider": provider, "phase": phase,
                  "attempt": attempts[phase]}

        def on_intent(value):
            if invocation["intent"] is not None or value.scratch_path != str(scratch):
                raise ValueError("foreign-edge bootstrap intent differs")
            record("mixed append bootstrap command intended", {
                **fields, "invocationId": value.invocation_id,
                "argvSha256": value.argv_sha256})
            invocation["intent"] = value

        def on_started(value):
            if (invocation["intent"] is None or invocation["started"] is not None
                    or value.intent != invocation["intent"]):
                raise ValueError("foreign-edge bootstrap start differs")
            identity = value.identity
            record("mixed append bootstrap command started before GO", {
                **fields, "invocationId": value.intent.invocation_id,
                "bootId": identity.boot_id, "pid": identity.pid,
                "pgid": identity.pgid, "startTicks": identity.start_ticks})
            invocation["started"] = value

        def on_result(value):
            if (invocation["started"] is None or invocation["result"] is not None
                    or value.started != invocation["started"]):
                raise ValueError("foreign-edge bootstrap result differs")
            record("mixed append bootstrap command result fenced", {
                **fields, "invocationId": value.started.intent.invocation_id,
                "returnCode": value.returncode,
                "stdoutTruncated": value.stdout_truncated,
                "stderrTruncated": value.stderr_truncated,
                **bootstrap_command_timing(value)})
            invocation["result"] = value

        def on_heartbeat(value):
            if value != invocation["started"] or invocation["result"] is not None:
                raise ValueError("foreign-edge bootstrap heartbeat differs")
            fence()

        fence()
        outcome = gated_command_runner(
            command, scratch_path=scratch, provider_keyed_v2=True,
            execution_timeout_seconds=BOOTSTRAP_COMMAND_TIMEOUT_SECONDS,
            env=dict(command_env), intent_callback=on_intent,
            started_callback=on_started,
            heartbeat_callback=on_heartbeat, result_callback=on_result)
        if (not isinstance(outcome, CommandResult)
                or invocation["result"] is None
                or outcome.started != invocation["started"]
                or invocation["result"].timed_out is not False
                or outcome.returncode != invocation["result"].returncode
                or outcome.stdout_truncated or outcome.stderr_truncated):
            raise ValueError("foreign-edge bootstrap command incomplete")
        if outcome.returncode == 0:
            completed.append(phase)
        return subprocess.CompletedProcess(command, outcome.returncode,
                                           outcome.stdout, outcome.stderr)

    fence()
    result = bootstrap_helper(
        source.engagement_id, chain, repository=jobs, env=bootstrap_env,
        workspace_root=scratch, host_policies=_host_policy(source, index),
        proxy_egress_ip=source.proxy_egress_ips[index],
        initial_sketch_known_hosts_path=workspace / ".barragan-sketch-known-hosts",
        pinned_core_known_hosts_path=Path(source.core_known_hosts_path),
        progress_reporter=reporter, runner=command_runner,
        required_source_root=Path(bootstrap_env[TEMPLATE_ROOT_ENV]),
        required_source_revision=source.source_revisions[index],
        only_edge_name=edge["hostname"],
    )
    if (not isinstance(result, SketchBootstrapApplyResult) or not first_contact
            or completed != [name for name, _ in _PHASES]
            or result.node_count != 1 or result.root_returncode != 0
            or result.user_readiness_returncode != 0
            or result.transport_returncode != 0):
        raise ValueError("foreign-edge bootstrap is incomplete")
    _clean_scratch_result(scratch)
    digest = job_event_digest(jobs.get(_child_id(source.parent_id)).events)
    record("mixed append edge bootstrap completed", {
        "provider": provider, "edgeAddress": edge["terraformAddress"],
        "bootstrapJournalSha256": digest})
    return digest


def validate_six_host_receipt_child(
    parent: StoredJobRun, child: StoredJobRun,
    receipt: SixHostProofReceipt, *, source: SixNodeHostSource,
) -> SixHostProofReceipt:
    """Reopen the exact terminal child and both private raw interpretations."""
    try:
        validate_six_node_host_source(source)
        if (type(receipt) is not SixHostProofReceipt
                or parent.id != source.parent_id or child.id != _child_id(parent.id)
                or receipt.parent_id != parent.id or receipt.child_id != child.id
                or receipt.source_sha256 != source.source_sha256
                or receipt.provider_order != source.provider_order
                or receipt.chain_ids != source.chain_ids
                or receipt.new_edge_addresses != source.new_edge_addresses
                or receipt.new_edge_ids != tuple(
                    chain.nodes[2]["providerInstanceId"] for chain in source.chains)
                or receipt.provider_proof_digests != source.provider_proof_digests
                or receipt.child_event_sha256 != job_event_digest(child.events)
                or child.action != ACTION or child.status != "succeeded"
                or child.finished_at is None or child.started_at is None
                or child.target_id != source.engagement_id
                or child.target != parent.target
                or child.input.get("parentJobId") != parent.id
                or child.input.get("sourceSha256") != source.source_sha256
                or child.input.get("mutation") is not True
                or child.input.get("claimOwner") != receipt.claim_owner
                or child.input.get("claimToken") != receipt.claim_token
                or not receipt.claim_owner.startswith(_OWNER_PREFIX)
                or not receipt.claim_token):
            raise ValueError("foreign-edge terminal host receipt differs")
        events = child.events
        if (len(events) < 7
                or [(event.sequence, event.level) for event in events]
                   != [(index, "info") for index in range(1, len(events) + 1)]
                or events[0].message != "mixed append host proof reserved"
                or events[0].data != {"sourceSha256": source.source_sha256}
                or events[1].message != "mixed append host proof started"
                or events[1].data != {"sourceSha256": source.source_sha256}
                or events[-1].message != "mixed append six-host proof completed"):
            raise ValueError("foreign-edge proof journal differs")
        terminal = events[-1].data
        if terminal != {
            "sourceSha256": source.source_sha256,
            "providerOrder": list(source.provider_order),
            "chainIds": list(source.chain_ids),
            "newEdgeAddresses": list(source.new_edge_addresses),
            "newEdgeIds": list(receipt.new_edge_ids),
            "providerProofDigests": list(source.provider_proof_digests),
            "bootstrapEventDigests": list(receipt.bootstrap_event_sha256s),
            "sketchKnownHostsDigests": list(receipt.sketch_known_hosts_sha256s),
            "rawProbeDigests": list(receipt.raw_probe_sha256s),
        }:
            raise ValueError("foreign-edge terminal data differs")
        if (len(receipt.sketch_known_hosts_sha256s) != 2
                or any(_HASH.fullmatch(value) is None
                       for value in receipt.sketch_known_hosts_sha256s)
                or any(_sketch_file_snapshot(
                    Path(source.workspace_paths[index]) /
                    ".barragan-sketch-known-hosts")[2]
                    != receipt.sketch_known_hosts_sha256s[index]
                    for index in range(2))):
            raise ValueError("foreign-edge retained trust changed")
        at = 2
        seen_invocations: set[str] = set()
        for index, provider in enumerate(source.provider_order):
            edge = source.chains[index].nodes[2]
            expected = (
                ("mixed append edge bootstrap intended", provider),
                ("mixed append edge first contact fenced", provider),
            )
            for message, selected in expected:
                if events[at].message != message or events[at].data.get("provider") != selected:
                    raise ValueError("foreign-edge bootstrap start differs")
                at += 1
            for phase, _ in _PHASES:
                at = _recognize_commands(events, at, provider, phase,
                                         "bootstrap", seen_invocations)
            completion = events[at]
            if (completion.message != "mixed append edge bootstrap completed"
                    or completion.data != {
                        "provider": provider, "edgeAddress": edge["terraformAddress"],
                        "bootstrapJournalSha256": receipt.bootstrap_event_sha256s[index],
                    }
                    or job_event_digest(events[:at])
                       != receipt.bootstrap_event_sha256s[index]):
                raise ValueError("foreign-edge bootstrap digest differs")
            at += 1
            if (events[at].message != "mixed append edge raw proof intended"
                    or events[at].data != {"provider": provider,
                                           "edgeAddress": edge["terraformAddress"]}):
                raise ValueError("foreign-edge raw proof intent differs")
            at += 1
            if (events[at].message != "mixed append edge raw scratch intended"
                    or events[at].data.get("provider") != provider):
                raise ValueError("foreign-edge raw scratch differs")
            at += 1
            raw_invocations = []
            for phase in ("metadata", "firewall_before", "surface", "firewall_after"):
                raw_invocations.append(events[at].data.get("invocationId"))
                at = _recognize_commands(events, at, provider, phase,
                                         "probe", seen_invocations)
            if (events[at].message != "mixed append edge raw proof captured"
                    or events[at].data != {
                        "provider": provider, "edgeAddress": edge["terraformAddress"],
                        "rawProbeSha256": receipt.raw_probe_sha256s[index],
                    }):
                raise ValueError("foreign-edge raw capture differs")
            collection = _read_collection(
                source, index, child.id, receipt.raw_probe_sha256s[index],
                receipt.sketch_known_hosts_sha256s[index])
            raw = collection.raw if provider == "linode" else collection
            if tuple(raw_invocations) != (
                    collection.identity.invocation_id,
                    raw.firewall_before.invocation_id,
                    raw.surface.invocation_id,
                    raw.firewall_after.invocation_id):
                raise ValueError("foreign-edge raw commands differ from journal")
            at += 1
        if at != len(events) - 1:
            raise ValueError("foreign-edge proof journal has extra events")
        return receipt
    except Exception as exc:
        raise MixedAppendPairHostProofAttention(
            "six-node host receipt needs exact read-only reconciliation") from exc


def _recognize_commands(events, at: int, provider: str, phase: str,
                        kind: str, seen: set[str]) -> int:
    stem = ("mixed append bootstrap command" if kind == "bootstrap"
            else "mixed append raw command")
    expected = (f"{stem} intended", f"{stem} started before GO",
                f"{stem} result fenced")
    attempt = 0
    return_codes = []
    while at + 2 < len(events) and events[at].message == expected[0] \
            and events[at].data.get("phase") == phase:
        intent, started, result = events[at:at + 3]
        attempt += 1
        invocation = intent.data.get("invocationId")
        if (tuple(item.message for item in (intent, started, result)) != expected
                or any(item.data.get("provider") != provider or
                       item.data.get("phase") != phase or
                       item.data.get("attempt") != attempt or
                       item.data.get("invocationId") != invocation
                       for item in (intent, started, result))
                or type(invocation) is not str or not invocation
                or invocation in seen
                or _HASH.fullmatch(str(intent.data.get("argvSha256"))) is None
                or not all(started.data.get(key) for key in (
                    "bootId", "pid", "pgid", "startTicks"))
                or type(result.data.get("returnCode")) is not int
                or result.data.get("stdoutTruncated") is not False
                or result.data.get("stderrTruncated") is not False):
            raise ValueError("foreign-edge command journal differs")
        if kind == "bootstrap":
            without_bootstrap_timing(result.data, success=True)
        seen.add(invocation)
        return_codes.append(result.data["returnCode"])
        at += 3
    if not return_codes or return_codes[-1] != 0 or (
            kind == "probe" and attempt != 1) or (
            kind == "bootstrap" and any(code == 0 for code in return_codes[:-1])):
        raise ValueError("foreign-edge command phase incomplete")
    return at


def _queued_host_reservation(parent, child, source) -> bool:
    """Recognize only the exact reservation before any claim or host contact."""
    try:
        created = datetime.fromisoformat(child.created_at)
        if created.utcoffset() not in (None, timedelta(0)):
            return False
        expected = StoredJobRun(
            _child_id(parent.id), ACTION, "queued", parent.target, "engagement",
            parent.target_id, parent.requested_by,
            {"parentJobId": parent.id, "sourceSha256": source.source_sha256,
             "mutation": True}, [], child.created_at, None, None,
            [JobEvent(1, "info", "mixed append host proof reserved",
                      {"sourceSha256": source.source_sha256})])
        return child == expected
    except (AttributeError, TypeError, ValueError):
        return False


def prove_mixed_append_pair_hosts(
    parent_id: str, *, environment: str, bootstrap_env: Mapping[str, str],
    fresh_source: Callable[[], SixNodeHostSource],
    job_repository=None, lease_lookup=None,
    bootstrap_helper: Callable = apply_sketch_bootstrap,
    gated_command_runner: Callable = run_gated_command,
    raw_collector: Callable = _probe_cross_provider_edge,
) -> SixHostProofReceipt:
    """One child reserves all routed contact; started contact never replays."""
    if environment != "devtest" or not callable(fresh_source):
        raise MixedAppendPairHostProofAttention("paired host proof is DevTest-only")
    jobs = job_repository or SqlAlchemyJobRepository()
    lookup = lease_lookup or _db_lease_lookup
    child_id = _child_id(parent_id)
    owner = f"{_OWNER_PREFIX}{uuid4().hex}"
    token = uuid4().hex
    child = parent_claim = None
    try:
        parent = jobs.get(parent_id)
        reserved = jobs.get(child_id)
        if (parent is None or parent.action != _OPERATION
                or parent.status != "running" or parent.finished_at is not None
                or parent.input.get("phase") != "apply_sealed"
                or (reserved is not None and getattr(reserved, "status", None) != "queued")
                or lookup(parent.target_id) != (parent.input["corePlanId"],
                                                    _OPERATION)
                or not isinstance(bootstrap_env, Mapping)
                or type(bootstrap_env.get(TEMPLATE_ROOT_ENV)) is not str):
            raise ValueError("paired host proof parent or lease differs")
        source = validate_six_node_host_source(fresh_source())
        source_sha = source.source_sha256
        if (source.parent_id != parent_id or source.engagement_id != parent.target_id
                or source.core_job_id != parent.input["coreJobId"]
                or source.core_plan_id != parent.input["corePlanId"]
                or tuple(parent.input["providerOrder"]) != source.provider_order
                or tuple(parent.input["chainOrder"]) != source.chain_ids):
            raise ValueError("paired host source differs from parent")
        if reserved is not None and not _queued_host_reservation(parent, reserved, source):
            raise ValueError("paired host reservation has already advanced or differs")
        for revision in source.source_revisions:
            require_pinned_sketch_ansible_source(
                env=bootstrap_env,
                required_source_root=Path(bootstrap_env[TEMPLATE_ROOT_ENV]),
                required_source_revision=revision)
        at = _now()
        parent_claim = jobs.claim_lease(
            parent.id, owner=owner, token=token, claimed_at=at,
            expires_at=_later(at), eligible_statuses={"running"},
            eligible_phases={"apply_sealed"})
        if parent_claim is None or jobs.get(child_id) != reserved:
            raise ValueError("paired host parent claim unavailable")
        proposed = StoredJobRun(
            child_id, ACTION, "queued", parent.target, "engagement",
            parent.target_id, parent.requested_by,
            {"parentJobId": parent.id, "sourceSha256": source.source_sha256,
             "mutation": True}, [], _now(), None, None,
            [JobEvent(1, "info", "mixed append host proof reserved",
                      {"sourceSha256": source.source_sha256})],
        )
        child = jobs.save_if_absent(proposed) if reserved is None else reserved
        # SQLite serializes UTC timestamps without their +00:00 suffix. Match
        # the exact authority/event grammar, not dataclass timestamp spelling.
        if not _queued_host_reservation(parent, child, source):
            raise ValueError("paired host child reservation raced")
        child = jobs.start_if_queued(
            child, started_at=_now(),
            event=JobEvent(2, "info", "mixed append host proof started",
                           {"sourceSha256": source.source_sha256}))
        if child is None:
            raise ValueError("paired host child start lost")
        at = _now()
        child = jobs.claim_lease(child_id, owner=owner, token=token,
                                 claimed_at=at, expires_at=_later(at),
                                 eligible_statuses={"running"})
        if child is None:
            raise ValueError("paired host child claim lost")

        def fence() -> None:
            nonlocal child, parent_claim
            if (lookup(parent.target_id) != (source.core_plan_id, _OPERATION)
                    or jobs.get(parent.id) != parent_claim
                    or jobs.get(child.id) != child):
                raise ValueError("paired host authority changed")
            now = _now()
            renewed_parent = jobs.renew_lease(
                parent.id, owner=owner, token=token,
                heartbeat_at=now, expires_at=_later(now))
            renewed_child = jobs.renew_lease(
                child.id, owner=owner, token=token,
                heartbeat_at=now, expires_at=_later(now))
            if (renewed_parent is None or renewed_child is None
                    or renewed_parent.events != parent_claim.events
                    or renewed_child.events != child.events):
                raise ValueError("paired host claim lost")
            parent_claim, child = renewed_parent, renewed_child

        def check_source() -> None:
            fence()
            fresh = validate_six_node_host_source(fresh_source())
            if (source.source_sha256 != source_sha
                    or fresh != source or fresh.source_sha256 != source_sha):
                raise ValueError("paired six-node state/provider proof changed")

        def record(message: str, data: dict) -> None:
            nonlocal child
            fence()
            at = _now()
            changed = jobs.append_event_if_running_claimed(
                child, owner=owner, token=token,
                expected_event_digest=job_event_digest(child.events),
                heartbeat_at=at, expires_at=_later(at),
                event=JobEvent(len(child.events) + 1, "info", message, data))
            if changed is None:
                raise ValueError("paired host journal CAS lost")
            child = changed

        bootstrap_digests = []
        sketch_digests = []
        raw_digests = []
        for index, provider in enumerate(source.provider_order):
            chain = source.chains[index]
            check_source()
            bootstrap_digests.append(_bootstrap_edge(
                source, index, jobs=jobs, bootstrap_env=bootstrap_env,
                fence=fence, record=record,
                bootstrap_helper=bootstrap_helper,
                gated_command_runner=gated_command_runner))
            check_source()
            sketch_digest = _sketch_file_snapshot(
                Path(source.workspace_paths[index]) /
                ".barragan-sketch-known-hosts")[2]
            if _HASH.fullmatch(sketch_digest) is None:
                raise ValueError("foreign-edge post-bootstrap trust differs")
            sketch_digests.append(sketch_digest)
            homebase, proxy = _core_hosts(
                jobs, source.engagement_id, chain.assigned_proxy,
                require_proxy_public_alias=True)
            middle, edges = _sketch_nodes(chain, require_exact_roles=True)
            unused = str(Path(source.workspace_paths[index]) / ".barragan-unused-proof-key")
            spec = SketchBootstrapSpec(
                homebase, proxy, middle, edges, unused, unused, unused, unused,
                unused, _host_policy(source, index), source.proxy_egress_ips[index],
                str(Path(source.workspace_paths[index]) / ".barragan-sketch-known-hosts"),
                source.core_known_hosts_path)
            edge = chain.nodes[2]
            record("mixed append edge raw proof intended", {
                "provider": provider, "edgeAddress": edge["terraformAddress"]})
            scratch = Path(source.workspace_paths[index]) / (
                f".barragan-mixed-append-proof-{uuid4().hex}")
            phase_index = 0

            def scratch_cb(value):
                record("mixed append edge raw scratch intended", {
                    "provider": provider, "scratchPath": value})

            def intent_cb(value):
                nonlocal phase_index
                phase = ("metadata", "firewall_before", "surface", "firewall_after")[phase_index]
                record("mixed append raw command intended", {
                    "provider": provider, "phase": phase, "attempt": 1,
                    "invocationId": value.invocation_id,
                    "argvSha256": value.argv_sha256})

            def started_cb(value):
                identity = value.identity
                phase = ("metadata", "firewall_before", "surface", "firewall_after")[phase_index]
                record("mixed append raw command started before GO", {
                    "provider": provider, "phase": phase, "attempt": 1,
                    "invocationId": value.intent.invocation_id,
                    "bootId": identity.boot_id, "pid": identity.pid,
                    "pgid": identity.pgid, "startTicks": identity.start_ticks})

            def result_cb(value):
                nonlocal phase_index
                phase = ("metadata", "firewall_before", "surface", "firewall_after")[phase_index]
                record("mixed append raw command result fenced", {
                    "provider": provider, "phase": phase, "attempt": 1,
                    "invocationId": value.started.intent.invocation_id,
                    "returnCode": value.returncode,
                    "stdoutTruncated": value.stdout_truncated,
                    "stderrTruncated": value.stderr_truncated})
                phase_index += 1

            collection = raw_collector(
                source, index, spec, scratch=scratch,
                sketch_known_hosts_sha256=sketch_digest, fence=fence,
                on_scratch=scratch_cb, on_intent=intent_cb,
                on_started=started_cb, on_heartbeat=lambda _value: fence(),
                on_result=result_cb, runner=gated_command_runner)
            if phase_index != 4:
                raise ValueError("foreign-edge raw commands incomplete")
            check_source()
            digest = _verify_cross_provider_collection(
                source, index, collection,
                sketch_known_hosts_sha256=sketch_digest)
            payload = json.dumps(asdict(collection), sort_keys=True,
                                 separators=(",", ":")).encode()
            if hashlib.sha256(payload).hexdigest() != digest:
                raise ValueError("foreign-edge raw collection digest differs")
            _write_private(_artifact_path(source, index, child_id), payload)
            raw_digests.append(digest)
            record("mixed append edge raw proof captured", {
                "provider": provider, "edgeAddress": edge["terraformAddress"],
                "rawProbeSha256": digest})
        check_source()
        terminal_data = {
            "sourceSha256": source.source_sha256,
            "providerOrder": list(source.provider_order),
            "chainIds": list(source.chain_ids),
            "newEdgeAddresses": list(source.new_edge_addresses),
            "newEdgeIds": [chain.nodes[2]["providerInstanceId"]
                           for chain in source.chains],
            "providerProofDigests": list(source.provider_proof_digests),
            "bootstrapEventDigests": bootstrap_digests,
            "sketchKnownHostsDigests": sketch_digests,
            "rawProbeDigests": raw_digests,
        }
        terminal = jobs.finish_if_running_claimed(
            child, owner=owner, token=token,
            expected_event_digest=job_event_digest(child.events),
            status="succeeded", finished_at=_now(),
            event=JobEvent(len(child.events) + 1, "info",
                           "mixed append six-host proof completed", terminal_data))
        if terminal is None:
            raise ValueError("paired host terminal CAS lost")
        receipt = SixHostProofReceipt(
            parent.id, child_id, source.source_sha256, source.provider_order,
            source.chain_ids, source.new_edge_addresses,
            tuple(chain.nodes[2]["providerInstanceId"] for chain in source.chains),
            source.provider_proof_digests, tuple(bootstrap_digests),
            tuple(sketch_digests), tuple(raw_digests),
            job_event_digest(terminal.events), owner, token)
        validate_six_host_receipt_child(parent_claim, terminal, receipt,
                                        source=validate_six_node_host_source(fresh_source()))
        return receipt
    except Exception as exc:
        timed_out = isinstance(exc, (SketchBootstrapTimeoutError, GatedCommandTimeoutError))
        # The inserted child is the permanent contact fence. A truthful failed
        # terminal helps the operator see attention, but is never a retry grant.
        try:
            latest = jobs.get(child_id)
            if (latest is not None and latest.status == "running"
                    and latest.input.get("claimOwner") == owner
                    and latest.input.get("claimToken") == token):
                jobs.finish_if_running_claimed(
                    latest, owner=owner, token=token,
                    expected_event_digest=job_event_digest(latest.events),
                    status="failed", finished_at=_now(),
                    event=JobEvent(len(latest.events) + 1, "error",
                                   BOOTSTRAP_TIMEOUT_MESSAGE if timed_out else
                                   "mixed append host proof stopped; reconciliation required",
                                   {"bootstrap": "reconciliation_required", "timedOut": True} if timed_out else {}))
        except Exception:
            pass
        raise MixedAppendPairHostProofAttention(
            BOOTSTRAP_TIMEOUT_MESSAGE if timed_out else
            "paired host contact stopped; never replay the reserved child") from exc
