# Copyright (c) 2026, Oracle and/or its affiliates.
import copy
import hashlib
import json
from pathlib import Path
import re
import shutil
import tomllib

import pytest

from app.services.sketch_provider_contract import (
    CONTRACT_ROOT,
    FAILURE_CODES,
    SketchProviderContractError,
    require_sketch_provider_contract,
    reviewed_contract_manifest,
)
import app.services.sketch_provider_contract as contract_module
from app.services.terraform_plan_gate import FirewallIngressDelta, FirewallIngressPort


FIXTURES = Path(__file__).parent / "fixtures" / "terraform-provider-contracts"
CASES = {
    ("no-op", "digitalocean"): ("digitalocean-edge.terraform-show.json", FirewallIngressDelta()),
    ("no-op", "linode"): ("linode-middle.terraform-show.json", FirewallIngressDelta()),
    ("remove", "digitalocean"): (
        "digitalocean-edge.terraform-show.json",
        FirewallIngressDelta(removed=frozenset({FirewallIngressPort("udp", 34791)})),
    ),
    ("remove", "linode"): (
        "linode-middle.terraform-show.json",
        FirewallIngressDelta(removed=frozenset({FirewallIngressPort("udp", 8000)})),
    ),
}


def _runtime(provider):
    manifest = reviewed_contract_manifest()
    return {
        "terraform_version": manifest["terraform"]["version"],
        "platform": manifest["terraform"]["platform"],
        "provider_selections": copy.deepcopy(manifest["providers"][provider]["selections"]),
    }


def _case(scenario, provider):
    filename, delta = CASES[(scenario, provider)]
    document = json.loads((FIXTURES / scenario / filename).read_text())
    lock = CONTRACT_ROOT / reviewed_contract_manifest()["providers"][provider]["lockFile"]
    return document, lock, delta


@pytest.mark.parametrize("scenario,provider", CASES)
def test_reviewed_real_provider_contracts_are_accepted(scenario, provider):
    document, lock, delta = _case(scenario, provider)
    accepted = require_sketch_provider_contract(
        provider,
        lock_path=lock,
        terraform_version=_runtime(provider),
        template_revision=reviewed_contract_manifest()["templateRevision"],
        sanitized_contract_projection=document,
        expected_delta=delta,
    )
    assert accepted.provider == provider
    assert accepted.terraform_version == "1.15.5"
    assert accepted.platform == "linux_amd64"
    assert accepted.firewall_schema_version == 0
    assert accepted.approved_changes == (() if scenario == "no-op" else ((
        "digitalocean_firewall.firewall" if provider == "digitalocean" else "linode_firewall.firewall",
        "update",
    ),))


def test_imported_evidence_is_only_reviewed_sanitized_noop_remove_and_canonical_locks():
    manifest = reviewed_contract_manifest()
    assert set(path.name for path in FIXTURES.iterdir()) == {"no-op", "remove"}
    files = sorted(path.relative_to(FIXTURES).as_posix() for path in FIXTURES.rglob("*") if path.is_file())
    assert files == [
        "no-op/digitalocean-edge.terraform-show.json",
        "no-op/linode-middle.terraform-show.json",
        "remove/digitalocean-edge.terraform-show.json",
        "remove/linode-middle.terraform-show.json",
    ]
    for scenario, contract in manifest["reviewedFixtures"].items():
        for provider, expected in contract["providers"].items():
            filename = CASES[(scenario, provider)][0]
            assert hashlib.sha256((FIXTURES / scenario / filename).read_bytes()).hexdigest() == expected["sha256"]
            packaged = CONTRACT_ROOT / expected["projectionFile"]
            assert packaged.read_bytes() == (FIXTURES / scenario / filename).read_bytes()
    for provider, contract in manifest["providers"].items():
        lock = CONTRACT_ROOT / contract["lockFile"]
        assert lock.name == ".terraform.lock.hcl"
        assert hashlib.sha256(lock.read_bytes()).hexdigest() == contract["lockSha256"]
    assert not any(
        token in path.name
        for path in FIXTURES.rglob("*")
        for token in ("tfstate", "tfplan", "raw", "stderr", "stdout", "key")
    )


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_missing_and_changed_lock_return_stable_codes(tmp_path, provider):
    document, lock, delta = _case("no-op", provider)
    common = dict(
        provider=provider, terraform_version=_runtime(provider),
        template_revision=reviewed_contract_manifest()["templateRevision"],
        sanitized_contract_projection=document, expected_delta=delta,
    )
    with pytest.raises(SketchProviderContractError) as missing:
        require_sketch_provider_contract(lock_path=tmp_path / "missing", **common)
    assert missing.value.code == "provider_lock_missing"
    changed = tmp_path / ".terraform.lock.hcl"
    changed.write_bytes(lock.read_bytes() + b"\n")
    with pytest.raises(SketchProviderContractError) as mismatch:
        require_sketch_provider_contract(lock_path=changed, **common)
    assert mismatch.value.code == "provider_lock_changed"


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("mutation", ["version", "platform", "extra-runtime-field"])
def test_runtime_contract_is_exact(provider, mutation):
    document, lock, delta = _case("no-op", provider)
    runtime = _runtime(provider)
    if mutation == "version": runtime["terraform_version"] = "1.15.6"
    elif mutation == "platform": runtime["platform"] = "darwin_arm64"
    else: runtime["unknown"] = True
    with pytest.raises(SketchProviderContractError) as error:
        require_sketch_provider_contract(
            provider, lock_path=lock, terraform_version=runtime,
            template_revision=reviewed_contract_manifest()["templateRevision"],
            sanitized_contract_projection=document, expected_delta=delta,
        )
    assert error.value.code == "terraform_runtime_unsupported"


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("mutation", ["missing", "extra", "version"])
def test_provider_selection_contract_is_exact(provider, mutation):
    document, lock, delta = _case("no-op", provider)
    runtime = _runtime(provider)
    selections = runtime["provider_selections"]
    if mutation == "missing": selections.pop(next(iter(selections)))
    elif mutation == "extra": selections["registry.terraform.io/hashicorp/null"] = "9.9.9"
    else: selections[next(iter(selections))] = "0.0.0"
    with pytest.raises(SketchProviderContractError) as error:
        require_sketch_provider_contract(
            provider, lock_path=lock, terraform_version=runtime,
            template_revision=reviewed_contract_manifest()["templateRevision"],
            sanitized_contract_projection=document, expected_delta=delta,
        )
    assert error.value.code == "provider_selection_unsupported"


def test_template_revision_plan_format_and_plan_runtime_are_exact():
    document, lock, delta = _case("no-op", "digitalocean")
    kwargs = dict(
        provider="digitalocean", lock_path=lock,
        terraform_version=_runtime("digitalocean"), expected_delta=delta,
    )
    with pytest.raises(SketchProviderContractError) as template:
        require_sketch_provider_contract(
            template_revision="0" * 40, sanitized_contract_projection=document, **kwargs,
        )
    assert template.value.code == "template_source_mismatch"
    changed = copy.deepcopy(document); changed["format_version"] = "1.3"
    with pytest.raises(SketchProviderContractError) as plan_format:
        require_sketch_provider_contract(
            template_revision=reviewed_contract_manifest()["templateRevision"],
            sanitized_contract_projection=changed, **kwargs,
        )
    assert plan_format.value.code == "plan_format_unsupported"
    changed = copy.deepcopy(document); changed["terraform_version"] = "1.15.6"
    with pytest.raises(SketchProviderContractError) as plan_runtime:
        require_sketch_provider_contract(
            template_revision=reviewed_contract_manifest()["templateRevision"],
            sanitized_contract_projection=changed, **kwargs,
        )
    assert plan_runtime.value.code == "terraform_runtime_unsupported"


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("value", [None, False, 1, "0", "extra"])
def test_firewall_resource_schema_is_exact_integer_zero(provider, value):
    document, lock, delta = _case("no-op", provider)
    target = f"{'digitalocean' if provider == 'digitalocean' else 'linode'}_firewall.firewall"
    resource = next(item for item in document["planned_values"]["root_module"]["resources"] if item["address"] == target)
    if value is None: resource.pop("schema_version")
    elif value == "extra": resource["unknown_metadata"] = False
    else: resource["schema_version"] = value
    with pytest.raises(SketchProviderContractError) as error:
        require_sketch_provider_contract(
            provider, lock_path=lock, terraform_version=_runtime(provider),
            template_revision=reviewed_contract_manifest()["templateRevision"],
            sanitized_contract_projection=document, expected_delta=delta,
        )
    assert error.value.code == (
        "plan_semantics_rejected" if value == "extra" else "resource_schema_unsupported"
    )


@pytest.mark.parametrize(
    "mutation", [
        "protected", "wrong-port", "deferred", "import", "replace", "generated",
        "unknown", "root-unknown", "malformed-unknown", "metadata", "drift-protected",
        "drift-unrelated", "drift-mask", "drift-mask-key", "drift-unknown",
    ],
)
def test_real_remove_plan_semantics_fail_closed(mutation):
    provider = "digitalocean"
    document, lock, delta = _case("remove", provider)
    change_resource = next(item for item in document["resource_changes"] if item["change"]["actions"] == ["update"])
    change = change_resource["change"]
    if mutation == "protected": change["after"]["name"] = "changed"
    elif mutation == "wrong-port":
        removed = next(rule for rule in change["before"]["inbound_rule"] if rule["port_range"] == "34791")
        removed["port_range"] = "34792"
    elif mutation == "deferred": document["deferred_changes"] = [{"resource_change": copy.deepcopy(change_resource)}]
    elif mutation == "import": change["importing"] = {"id": "opaque"}
    elif mutation == "replace": change["replace_paths"] = [["name"]]
    elif mutation == "generated": change_resource["generated_config"] = "resource opaque {}"
    elif mutation == "unknown": change["after_unknown"]["name"] = True
    elif mutation == "root-unknown": change["after_unknown"] = True
    elif mutation == "malformed-unknown": change["after_unknown"]["status"] = "false"
    elif mutation == "metadata": change_resource["provider_name"] = "registry.terraform.io/hashicorp/local"
    elif mutation == "drift-protected": document["resource_drift"][0]["change"]["after"]["name"] = "changed"
    elif mutation == "drift-unrelated": document["resource_drift"][0]["address"] = "digitalocean_droplet.edge[0]"
    elif mutation == "drift-mask": document["resource_drift"][0]["change"]["after_sensitive"]["name"] = True
    elif mutation == "drift-mask-key": document["resource_drift"][0]["change"]["after_sensitive"]["not_a_value"] = False
    elif mutation == "drift-unknown": document["resource_drift"][0]["change"]["after_unknown"] = "malformed"
    with pytest.raises(SketchProviderContractError) as error:
        require_sketch_provider_contract(
            provider, lock_path=lock, terraform_version=_runtime(provider),
            template_revision=reviewed_contract_manifest()["templateRevision"],
            sanitized_contract_projection=document, expected_delta=delta,
        )
    assert error.value.code == "plan_semantics_rejected"


@pytest.mark.parametrize("mutation", ["changed-noop", "unknown-noop"])
def test_noop_resource_changes_are_exact_and_known(mutation):
    provider = "digitalocean"
    document, lock, delta = _case("no-op", provider)
    change = document["resource_changes"][0]["change"]
    if mutation == "changed-noop":
        change["after"] = copy.deepcopy(change["before"])
        change["after"]["provider_payload"] = "changed"
    else:
        change["after_unknown"] = {"status": True}
    with pytest.raises(SketchProviderContractError) as error:
        require_sketch_provider_contract(
            provider, lock_path=lock, terraform_version=_runtime(provider),
            template_revision=reviewed_contract_manifest()["templateRevision"],
            sanitized_contract_projection=document, expected_delta=delta,
        )
    assert error.value.code == "plan_semantics_rejected"


def test_failure_codes_are_the_claimed_stable_contract():
    assert FAILURE_CODES == {
        "provider_lock_missing", "provider_lock_changed", "provider_selection_unsupported",
        "terraform_runtime_unsupported", "template_source_mismatch",
        "plan_format_unsupported", "resource_schema_unsupported", "plan_semantics_rejected",
    }


def _require_rejected(document, provider, delta, code="plan_semantics_rejected"):
    _original, lock, _original_delta = _case("no-op", provider)
    with pytest.raises(SketchProviderContractError) as error:
        require_sketch_provider_contract(
            provider, lock_path=lock, terraform_version=_runtime(provider),
            template_revision=reviewed_contract_manifest()["templateRevision"],
            sanitized_contract_projection=document, expected_delta=delta,
        )
    assert error.value.code == code


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize(
    "mutation", ["delete", "arbitrary", "missing", "extra", "mask", "unknown", "noop-diff", "noop-type"],
)
def test_complete_output_contract_rejects_unreviewed_changes(provider, mutation):
    document, _lock, delta = _case("no-op", provider)
    outputs = document["output_changes"]
    updated = next(value for value in outputs.values() if value["actions"] == ["update"])
    if mutation == "delete": updated["actions"] = ["delete"]
    elif mutation == "arbitrary": updated["after"] = "arbitrary output"
    elif mutation == "missing": outputs.pop(next(iter(outputs)))
    elif mutation == "extra": outputs["output_999"] = copy.deepcopy(updated)
    elif mutation == "mask": updated["after_sensitive"] = True
    elif mutation == "unknown": updated["after_unknown"] = {"value": True}
    elif mutation == "noop-diff":
        noop = next(value for value in outputs.values() if value["actions"] == ["no-op"])
        noop["after"] = "changed"
    else:
        outputs["output_001"]["before"] = {}
        outputs["output_001"]["after"] = {}
    _require_rejected(document, provider, delta)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize(
    "mutation", ["top-extra", "top-missing", "sibling-provider", "sibling-schema",
                 "sibling-address", "sibling-extra", "resource-extra",
                 "sibling-bool-index", "change-sibling-provider", "change-sibling-address",
                 "change-sibling-extra", "change-sibling-bool-index"],
)
def test_full_plan_and_resource_inventory_is_exact(provider, mutation):
    document, _lock, delta = _case("no-op", provider)
    resources = document["planned_values"]["root_module"]["resources"]
    sibling = next(resource for resource in resources if not resource["address"].endswith("_firewall.firewall"))
    if mutation == "top-extra": document["unknown_section"] = {}
    elif mutation == "top-missing": document.pop("checks")
    elif mutation == "sibling-provider": sibling["provider_name"] = "registry.terraform.io/hashicorp/local"
    elif mutation == "sibling-schema": sibling["schema_version"] += 1
    elif mutation == "sibling-address": sibling["address"] = "unknown_resource.resource_999"
    elif mutation == "sibling-extra": sibling["deposed"] = "opaque"
    elif mutation == "resource-extra": resources.append(copy.deepcopy(sibling))
    elif mutation == "sibling-bool-index": sibling["index"] = False
    else:
        change_sibling = next(
            resource for resource in document["resource_changes"]
            if not resource["address"].endswith("_firewall.firewall")
        )
        if mutation == "change-sibling-provider":
            change_sibling["provider_name"] = "registry.terraform.io/hashicorp/local"
        elif mutation == "change-sibling-address":
            change_sibling["address"] = "unknown_resource.resource_999"
        elif mutation == "change-sibling-bool-index":
            change_sibling["index"] = False
        else:
            change_sibling["deposed"] = "opaque"
    _require_rejected(document, provider, delta)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
@pytest.mark.parametrize("mutation", ["sensitive-true", "mask-key", "unknown-type", "unknown-key"])
def test_selected_remove_masks_and_unknowns_bind_to_values(provider, mutation):
    document, _lock, delta = _case("remove", provider)
    change = next(item["change"] for item in document["resource_changes"] if item["change"]["actions"] == ["update"])
    ingress = "inbound_rule" if provider == "digitalocean" else "inbound"
    if mutation == "sensitive-true": change["after_sensitive"][ingress][0][next(iter(change["after_sensitive"][ingress][0]))] = True
    elif mutation == "mask-key": change["after_sensitive"][ingress][0]["not_a_rule_field"] = False
    elif mutation == "unknown-type": change["after_unknown"] = "malformed"
    else: change["after_unknown"]["not_a_value_field"] = False
    _require_rejected(document, provider, delta)


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_add_is_rejected_until_a_reviewed_add_fixture_exists(provider):
    document, _lock, _delta = _case("no-op", provider)
    delta = FirewallIngressDelta(added=frozenset({FirewallIngressPort("udp", 31337)}))
    _require_rejected(document, provider, delta)


@pytest.mark.parametrize(
    "mutation", ["missing", "extra", "wrong-type", "nested-extra", "bad-lock-digest",
                 "bad-revision", "bad-provider-version", "bad-fixture-record",
                 "provider-extra", "fixture-digest-type", "bad-output-record"],
)
def test_manifest_schema_is_fully_pinned_and_malformed_forms_are_stable(tmp_path, monkeypatch, mutation):
    manifest = copy.deepcopy(reviewed_contract_manifest())
    if mutation == "missing": manifest.pop("plan")
    elif mutation == "extra": manifest["unknown"] = False
    elif mutation == "wrong-type": manifest["contractVersion"] = True
    elif mutation == "nested-extra": manifest["terraform"]["unknown"] = False
    elif mutation == "bad-lock-digest": manifest["providers"]["digitalocean"]["lockSha256"] = "0" * 64
    elif mutation == "bad-revision": manifest["templateRevision"] = "0" * 40
    elif mutation == "bad-provider-version": manifest["providers"]["linode"]["selections"]["registry.terraform.io/linode/linode"] = 4
    elif mutation == "bad-fixture-record": manifest["reviewedFixtures"]["remove"]["providers"].pop("linode")
    elif mutation == "provider-extra": manifest["providers"]["unsupported"] = {}
    elif mutation == "fixture-digest-type": manifest["reviewedFixtures"]["no-op"]["manifestSha256"] = 1
    else: manifest["providers"]["digitalocean"]["materializedPathOutputs"]["output_006"]["unknown"] = False
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    monkeypatch.setattr(contract_module, "MANIFEST_PATH", path)
    with pytest.raises(SketchProviderContractError) as error:
        reviewed_contract_manifest()
    assert error.value.code == "provider_selection_unsupported"


def test_backend_package_data_declares_exact_contract_content():
    backend = Path(__file__).parents[1]
    config = tomllib.loads((backend / "pyproject.toml").read_text(encoding="utf-8"))
    declared = config["tool"]["setuptools"]["package-data"]["app"]
    assert declared == [
        "provider_contracts/sketch/manifest.json",
        "provider_contracts/sketch/digitalocean/.terraform.lock.hcl",
        "provider_contracts/sketch/linode/.terraform.lock.hcl",
        "provider_contracts/sketch/projections/no-op/digitalocean-edge.terraform-show.json",
        "provider_contracts/sketch/projections/no-op/linode-middle.terraform-show.json",
        "provider_contracts/sketch/projections/remove/digitalocean-edge.terraform-show.json",
        "provider_contracts/sketch/projections/remove/linode-middle.terraform-show.json",
    ]
    packaged = [backend / "app" / relative for relative in declared]
    assert all(path.is_file() for path in packaged)
    manifest = reviewed_contract_manifest()
    for provider, path in zip(("digitalocean", "linode"), packaged[1:3], strict=True):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == manifest["providers"][provider]["lockSha256"]
    assert {
        hashlib.sha256(path.read_bytes()).hexdigest() for path in packaged[3:]
    } == {
        record["sha256"]
        for scenario in manifest["reviewedFixtures"].values()
        for record in scenario["providers"].values()
    }


@pytest.mark.parametrize("content", ["{", '{"contractVersion": 1, "contractVersion": 1}', '{"contractVersion": NaN}'])
def test_malformed_or_duplicate_manifest_json_has_stable_failure(tmp_path, monkeypatch, content):
    path = tmp_path / "manifest.json"
    path.write_text(content, encoding="utf-8")
    monkeypatch.setattr(contract_module, "MANIFEST_PATH", path)
    with pytest.raises(SketchProviderContractError) as error:
        reviewed_contract_manifest()
    assert error.value.code == "provider_selection_unsupported"


def test_non_utf8_manifest_has_stable_failure(tmp_path, monkeypatch):
    path = tmp_path / "manifest.json"
    path.write_bytes(b"\xff")
    monkeypatch.setattr(contract_module, "MANIFEST_PATH", path)
    with pytest.raises(SketchProviderContractError) as error:
        reviewed_contract_manifest()
    assert error.value.code == "provider_selection_unsupported"


@pytest.mark.parametrize(
    "surface", ["planned-change-mismatch", "sibling-mask", "check", "configuration",
                "prior-state", "variables", "planned-outputs", "relevant-attributes",
                "raw-output-secret"],
)
def test_full_projection_comparison_rejects_every_unreviewed_surface(surface):
    scenario = "remove" if surface == "relevant-attributes" else "no-op"
    provider = "digitalocean"
    document, _lock, delta = _case(scenario, provider)
    if surface == "planned-change-mismatch":
        firewall = next(item for item in document["planned_values"]["root_module"]["resources"] if item["address"] == "digitalocean_firewall.firewall")
        firewall["values"]["name"] = "<redacted-0000000000000001>"
    elif surface == "sibling-mask": document["resource_changes"][0]["change"]["before_sensitive"]["not_a_value"] = False
    elif surface == "check": document["checks"][0]["status"] = "fail"
    elif surface == "configuration": document["configuration"]["root_module"]["variables"]["var_001"]["unknown"] = False
    elif surface == "prior-state": document["prior_state"]["unknown"] = False
    elif surface == "variables": document["variables"]["var_001"]["value"] = "<redacted-0000000000000002>"
    elif surface == "planned-outputs": document["planned_values"]["outputs"]["output_001"]["sensitive"] = True
    elif surface == "relevant-attributes": document["relevant_attributes"][0]["attribute"].append("extra")
    else:
        document["output_changes"]["output_001"]["before"] = "RAW-SECRET"
        document["output_changes"]["output_001"]["after"] = "RAW-SECRET"
    _require_rejected(document, provider, delta)


def _replace_redacted_tokens(value, replacements):
    if isinstance(value, dict):
        return {key: _replace_redacted_tokens(child, replacements) for key, child in value.items()}
    if isinstance(value, list):
        return [_replace_redacted_tokens(child, replacements) for child in value]
    if isinstance(value, str) and re.fullmatch(r"<redacted-[0-9a-f]{16}>", value):
        return replacements.get(value, value)
    return value


def _redacted_tokens(value):
    if isinstance(value, dict):
        return [token for child in value.values() for token in _redacted_tokens(child)]
    if isinstance(value, list):
        return [token for child in value for token in _redacted_tokens(child)]
    return [value] if isinstance(value, str) and re.fullmatch(r"<redacted-[0-9a-f]{16}>", value) else []


@pytest.mark.parametrize("provider", ["digitalocean", "linode"])
def test_projection_allows_only_document_wide_bijective_redaction_changes(provider):
    document, lock, delta = _case("no-op", provider)
    tokens = sorted(set(_redacted_tokens(document)))
    replacements = {token: f"<redacted-{index + 0xF000000000000000:016x}>" for index, token in enumerate(tokens)}
    candidate = _replace_redacted_tokens(document, replacements)
    accepted = require_sketch_provider_contract(
        provider, lock_path=lock, terraform_version=_runtime(provider),
        template_revision=reviewed_contract_manifest()["templateRevision"],
        sanitized_contract_projection=candidate, expected_delta=delta,
    )
    assert accepted.scenario == "no-op"


@pytest.mark.parametrize("failure", ["collision", "inconsistent"])
def test_projection_rejects_redaction_collision_or_inconsistent_repeat(failure):
    provider = "digitalocean"
    document, _lock, delta = _case("no-op", provider)
    tokens = _redacted_tokens(document)
    if failure == "collision":
        distinct = list(dict.fromkeys(tokens))[:2]
        candidate = _replace_redacted_tokens(document, {distinct[0]: "<redacted-ffffffffffffffff>", distinct[1]: "<redacted-ffffffffffffffff>"})
    else:
        repeated = next(token for token in set(tokens) if tokens.count(token) > 1)
        candidate = copy.deepcopy(document)
        seen = 0
        def change_one(value):
            nonlocal seen
            if isinstance(value, dict):
                for key in value: value[key] = change_one(value[key])
            elif isinstance(value, list):
                for index in range(len(value)): value[index] = change_one(value[index])
            elif value == repeated:
                seen += 1
                if seen == 2: return "<redacted-eeeeeeeeeeeeeeee>"
            return value
        candidate = change_one(candidate)
    _require_rejected(candidate, provider, delta)


@pytest.mark.parametrize("timestamp,accepted", [
    ("2026-09-15T21:22:23Z", True),
    ("2026-09-15T21:22:23.123456+00:00", True),
    ("2026-99-15T21:22:23Z", False),
    ("September 15", False),
])
def test_projection_timestamp_has_strict_contract(timestamp, accepted):
    provider = "digitalocean"
    document, lock, delta = _case("no-op", provider)
    document["timestamp"] = timestamp
    if accepted:
        require_sketch_provider_contract(
            provider, lock_path=lock, terraform_version=_runtime(provider),
            template_revision=reviewed_contract_manifest()["templateRevision"],
            sanitized_contract_projection=document, expected_delta=delta,
        )
    else:
        _require_rejected(document, provider, delta)


def test_reviewed_projection_digest_tamper_rejects_before_comparison(tmp_path, monkeypatch):
    copied = tmp_path / "sketch"
    shutil.copytree(CONTRACT_ROOT, copied)
    projection = copied / "projections/no-op/digitalocean-edge.terraform-show.json"
    projection.write_bytes(projection.read_bytes() + b" ")
    monkeypatch.setattr(contract_module, "CONTRACT_ROOT", copied)
    document, _lock, delta = _case("no-op", "digitalocean")
    _require_rejected(document, "digitalocean", delta)


@pytest.mark.parametrize("provider", [None, 1, [], {}, set()])
def test_malformed_provider_inputs_have_stable_failure(provider):
    document, lock, delta = _case("no-op", "digitalocean")
    with pytest.raises(SketchProviderContractError) as error:
        require_sketch_provider_contract(
            provider, lock_path=lock, terraform_version=_runtime("digitalocean"),
            template_revision=reviewed_contract_manifest()["templateRevision"],
            sanitized_contract_projection=document, expected_delta=delta,
        )
    assert error.value.code == "provider_selection_unsupported"


@pytest.mark.parametrize(
    "location,value", [
        ("planned", None), ("planned", "bad"), ("planned", []),
        ("root", None), ("root", "bad"), ("root", []),
        ("resources", None), ("resources", "bad"), ("resources", {}),
    ],
)
def test_malformed_planned_resource_containers_have_stable_failure(location, value):
    provider = "digitalocean"
    document, lock, delta = _case("no-op", provider)
    if location == "planned": document["planned_values"] = value
    elif location == "root": document["planned_values"]["root_module"] = value
    else: document["planned_values"]["root_module"]["resources"] = value
    with pytest.raises(SketchProviderContractError) as error:
        require_sketch_provider_contract(
            provider, lock_path=lock, terraform_version=_runtime(provider),
            template_revision=reviewed_contract_manifest()["templateRevision"],
            sanitized_contract_projection=document, expected_delta=delta,
        )
    assert error.value.code == "resource_schema_unsupported"
