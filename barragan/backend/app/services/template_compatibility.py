# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from app.services.redteam_infra_template import (
    RedteamInfraTemplateSource,
    resolve_redteam_infra_template_source,
)


GitRunner = Callable[[Path, list[str]], str]


@dataclass(frozen=True)
class TemplateCompatibilityCheck:
    id: str
    status: str
    severity: str
    message: str
    path: str = ""

    def to_dict(self) -> dict[str, str]:
        body = {
            "id": self.id,
            "status": self.status,
            "severity": self.severity,
            "message": self.message,
        }
        if self.path:
            body["path"] = self.path
        return body


@dataclass(frozen=True)
class TemplateCompatibilityReport:
    source: RedteamInfraTemplateSource
    git: dict[str, object]
    status: str
    checks: tuple[TemplateCompatibilityCheck, ...]

    def to_dict(self) -> dict[str, object]:
        return {
            "source": {
                "path": str(self.source.root),
                "kind": self.source.source,
                "warning": self.source.warning,
            },
            "git": self.git,
            "status": self.status,
            "checks": [check.to_dict() for check in self.checks],
        }


REQUIRED_PATHS = (
    ("desktop.google_chrome.role", ("ansible", "roles", "google-chrome")),
    ("desktop.firefox.role", ("ansible", "roles", "firefox")),
    ("desktop.keepassxc.role", ("ansible", "roles", "keepassxc")),
    ("desktop.libreoffice.role", ("ansible", "roles", "libreoffice")),
    ("desktop.vs_code.role", ("ansible", "roles", "vs-code")),
    ("backflips.role", ("ansible", "roles", "backflips")),
    ("sketch.linode.template", ("external", "sketch", "linode")),
    ("sketch.digitalocean.template", ("external", "sketch", "digitalocean")),
)


def audit_redteam_infra_template(
    *,
    source: RedteamInfraTemplateSource | None = None,
    git_runner: GitRunner | None = None,
) -> TemplateCompatibilityReport:
    resolved = source or resolve_redteam_infra_template_source()
    checks = [
        *_required_path_checks(resolved),
        _digitalocean_udp_ports_check(resolved),
        *_sketch_bootstrap_inventory_checks(resolved),
    ]
    return TemplateCompatibilityReport(
        source=resolved,
        git=_git_metadata(resolved.root, git_runner=git_runner),
        status=_aggregate_status(checks),
        checks=tuple(checks),
    )


def _required_path_checks(source: RedteamInfraTemplateSource) -> list[TemplateCompatibilityCheck]:
    checks: list[TemplateCompatibilityCheck] = []
    for check_id, parts in REQUIRED_PATHS:
        path = source.path(*parts)
        if path.exists():
            checks.append(
                TemplateCompatibilityCheck(
                    check_id,
                    "pass",
                    "blocking",
                    "Required template path exists.",
                    _relative_path(source.root, path),
                )
            )
        else:
            checks.append(
                TemplateCompatibilityCheck(
                    check_id,
                    "fail",
                    "blocking",
                    "Required template path is missing.",
                    _relative_path(source.root, path),
                )
            )
    return checks


def _digitalocean_udp_ports_check(source: RedteamInfraTemplateSource) -> TemplateCompatibilityCheck:
    variables = source.path("external", "sketch", "digitalocean", "variables.tf")
    firewall = source.path("external", "sketch", "digitalocean", "firewall.tf")
    variables_text = _read_text(variables)
    firewall_text = _read_text(firewall)
    ok = 'variable "allowed_udp_ports"' in variables_text and "for_each = var.allowed_udp_ports" in firewall_text
    return TemplateCompatibilityCheck(
        "sketch.digitalocean.allowed_udp_ports",
        "pass" if ok else "fail",
        "blocking",
        (
            "DigitalOcean sketch template supports explicit UDP ingress ports."
            if ok
            else "DigitalOcean sketch template does not support explicit UDP ingress ports."
        ),
        "external/sketch/digitalocean",
    )


def _sketch_bootstrap_inventory_checks(source: RedteamInfraTemplateSource) -> list[TemplateCompatibilityCheck]:
    checks: list[TemplateCompatibilityCheck] = []
    for provider in ("linode", "digitalocean"):
        path = source.path("external", "sketch", provider, "templates", "inventory.tftpl")
        content = _read_text(path)
        if "ansible_ssh_user=root" in content:
            checks.append(
                TemplateCompatibilityCheck(
                    f"sketch.{provider}.bootstrap_root_ssh",
                    "pass",
                    "info",
                    "Sketch bootstrap inventory uses root SSH; this is compatible with legacy redteam-infra bootstrap.",
                    _relative_path(source.root, path),
                )
            )
        elif "ansible_ssh_user=" in content:
            checks.append(
                TemplateCompatibilityCheck(
                    f"sketch.{provider}.bootstrap_ssh_user",
                    "pass",
                    "info",
                    "Sketch bootstrap inventory declares an explicit Ansible SSH user.",
                    _relative_path(source.root, path),
                )
            )
        else:
            checks.append(
                TemplateCompatibilityCheck(
                    f"sketch.{provider}.bootstrap_ssh_user",
                    "warning",
                    "advisory",
                    "Sketch bootstrap inventory does not declare ansible_ssh_user.",
                    _relative_path(source.root, path),
                )
            )
    return checks


def _git_metadata(root: Path, *, git_runner: GitRunner | None = None) -> dict[str, object]:
    is_checkout = (root / ".git").exists()
    body: dict[str, object] = {"isCheckout": is_checkout}
    if not is_checkout:
        return body
    runner = git_runner or _run_git
    body["branch"] = _git_value(root, ["branch", "--show-current"], runner)
    body["commit"] = _git_value(root, ["rev-parse", "HEAD"], runner)
    status = _git_value(root, ["status", "--porcelain"], runner)
    body["dirty"] = bool(status.strip())
    return body


def _git_value(root: Path, args: list[str], runner: GitRunner) -> str:
    try:
        return runner(root, args).strip()
    except Exception:
        return ""


def _run_git(root: Path, args: list[str]) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return ""
    return result.stdout


def _aggregate_status(checks: list[TemplateCompatibilityCheck]) -> str:
    if any(check.status == "fail" and check.severity == "blocking" for check in checks):
        return "failed"
    if any(check.status in {"fail", "warning"} for check in checks):
        return "warning"
    return "passed"


def _read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8")


def _relative_path(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def ensure_sketch_resource_name_suffix_compatibility(workspace: Path, provider: str) -> list[str]:
    """Adapt a copied legacy sketch workspace to Barragan's collision-safe inputs."""

    if provider not in {"linode", "digitalocean"}:
        raise ValueError(f"unsupported sketch provider: {provider}")

    changed: list[str] = []
    variables_tf = workspace / "variables.tf"
    if variables_tf.exists():
        text = variables_tf.read_text(encoding="utf-8")
        missing_blocks = []
        if 'variable "resource_name_suffix"' not in text:
            missing_blocks.append(
                '\nvariable "resource_name_suffix" {\n'
                "  description = \"Stable suffix for avoiding same-engagement sketch resource collisions.\"\n"
                '  default     = ""\n'
                "}\n"
            )
        if 'variable "middle_ordinal"' not in text:
            missing_blocks.append(
                '\nvariable "middle_ordinal" {\n'
                "  description = \"Engagement-wide ordinal for the chain middle label.\"\n"
                "  default     = 1\n"
                "}\n"
            )
        if 'variable "edge_ordinal"' not in text:
            missing_blocks.append(
                '\nvariable "edge_ordinal" {\n'
                "  description = \"Engagement-wide ordinal for the first edge label.\"\n"
                "  default     = 1\n"
                "}\n"
            )
        if missing_blocks:
            variables_tf.write_text(text.rstrip() + "".join(missing_blocks), encoding="utf-8")
            changed.append("variables.tf")

    replacements = {
        "middle.tf": {
            '${var.engagement_name}"': '${var.engagement_name}${var.resource_name_suffix}"',
            'middle${format("%02g", count.index + 1)}-': 'middle${format("%02g", count.index + var.middle_ordinal)}-',
        },
        "edge.tf": {
            '${format("%02g", (count.index % var.edge_count_per_region) + 1)}"': '${format("%02g", (count.index % var.edge_count_per_region) + var.edge_ordinal)}${var.resource_name_suffix}"',
        },
        "firewall.tf": {
            '${var.engagement_name}-firewall"': '${var.engagement_name}${var.resource_name_suffix}-firewall"',
            'allow-${var.engagement_name}-host-': 'allow-${var.engagement_name}${var.resource_name_suffix}-host-',
        },
    }
    for filename, file_replacements in replacements.items():
        path = workspace / filename
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        updated = text
        for original, replacement in file_replacements.items():
            updated = updated.replace(original, replacement)
        if updated != text:
            path.write_text(updated, encoding="utf-8")
            changed.append(filename)
    return changed


def ensure_sketch_ssh_variable_contract_compatibility(workspace: Path, provider: str) -> list[str]:
    """Repair a retained workspace whose variables came from another revision."""

    if provider not in {"linode", "digitalocean"}:
        raise ValueError(f"unsupported sketch provider: {provider}")
    variables_tf = workspace / "variables.tf"
    main_tf = workspace / "main.tf"
    if not variables_tf.exists() or not main_tf.exists():
        return []
    variables_text = variables_tf.read_text(encoding="utf-8")
    main_text = main_tf.read_text(encoding="utf-8")
    missing = [
        name
        for name in ("ssh_pub_key_path", "ssh_priv_key_path")
        if f"var.{name}" in main_text and f'variable "{name}"' not in variables_text
    ]
    if not missing:
        return []
    blocks = "".join(f'\n\nvariable "{name}" {{\n  default = ""\n}}' for name in missing)
    variables_tf.write_text(variables_text.rstrip() + blocks + "\n", encoding="utf-8")
    return ["variables.tf"]


def stabilize_digitalocean_ssh_key_ownership(workspace: Path) -> str:
    """Pin a retained DigitalOcean workspace to its established SSH-key mode.

    Stock redteam-infra conditionally creates an account SSH key when a public
    key lookup is empty. In the workspace that created the key, a later apply
    can observe that same key through the data source, destroy the managed key,
    and recreate every droplet on the following apply. State already tells us
    whether this copied workspace owns or borrows the key, so make that choice
    durable before Barragan performs any retained-workspace mutation.
    """

    providers_tf = workspace / "providers.tf"
    state_file = workspace / "terraform.tfstate"
    if not providers_tf.exists() or not state_file.exists():
        return "unresolved"
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return "unresolved"
    resources = state.get("resources") if isinstance(state, dict) else None
    if not isinstance(resources, list):
        return "unresolved"

    owns_key = any(
        isinstance(resource, dict)
        and resource.get("mode") == "managed"
        and resource.get("type") == "digitalocean_ssh_key"
        and resource.get("name") == "key"
        and bool(resource.get("instances"))
        for resource in resources
    )
    borrows_key = any(
        isinstance(resource, dict)
        and resource.get("mode") == "data"
        and resource.get("type") == "digitalocean_ssh_keys"
        and resource.get("name") == "matching_key"
        and any(
            isinstance(instance, dict)
            and isinstance(instance.get("attributes"), dict)
            and bool(instance["attributes"].get("ssh_keys"))
            for instance in resource.get("instances") or []
        )
        for resource in resources
    )
    if not owns_key and not borrows_key:
        return "unresolved"

    text = providers_tf.read_text(encoding="utf-8")
    if (
        owns_key
        and "count      = 1" in text
        and "sketch_ssh_key_id = digitalocean_ssh_key.key[0].id" in text
        and 'data "digitalocean_ssh_keys" "matching_key"' not in text
    ):
        return "owner"
    if (
        not owns_key
        and borrows_key
        and "count      = 0" in text
        and "sketch_ssh_key_id = data.digitalocean_ssh_keys.matching_key.ssh_keys[0].id" in text
    ):
        return "borrower"
    start = text.find('data "digitalocean_ssh_keys" "matching_key"')
    if start < 0:
        start = text.find('resource "digitalocean_ssh_key" "key"')
    end = text.find('provider "local"', start)
    if start < 0 or end < 0:
        return "unresolved"

    resource = (
        'resource "digitalocean_ssh_key" "key" {\n'
        f"  count      = {1 if owns_key else 0}\n"
        '  name       = "do-key"\n'
        "  public_key = chomp(file(local.ssh_pub_key_path))\n"
        "}\n\n"
    )
    if owns_key:
        replacement = (
            resource
            + "locals {\n"
            + "  sketch_ssh_key_id = digitalocean_ssh_key.key[0].id\n"
            + "}\n\n"
        )
        mode = "owner"
    else:
        replacement = (
            'data "digitalocean_ssh_keys" "matching_key" {\n'
            "  filter {\n"
            '    key    = "public_key"\n'
            "    values = [chomp(file(local.ssh_pub_key_path))]\n"
            "  }\n"
            "}\n\n"
            + resource
            + "locals {\n"
            + "  sketch_ssh_key_id = data.digitalocean_ssh_keys.matching_key.ssh_keys[0].id\n"
            + "}\n\n"
        )
        mode = "borrower"

    updated = text[:start] + replacement + text[end:]
    if updated != text:
        providers_tf.write_text(updated, encoding="utf-8")
    return mode


def prepare_digitalocean_ssh_key_reuse(workspace: Path) -> str:
    """Make a fresh copied DigitalOcean workspace borrow an existing key.

    The stock template still unconditionally creates an account SSH key. That
    works for an engagement's first DigitalOcean chain, but a second copied
    workspace with the same engagement-scoped public key receives a provider
    422. Established workspaces are pinned first; only an unresolved fresh
    workspace receives the conditional matching-key form.
    """

    mode = stabilize_digitalocean_ssh_key_ownership(workspace)
    if mode != "unresolved":
        _normalize_digitalocean_sketch_key_references(workspace)
        return mode
    providers_tf = workspace / "providers.tf"
    if not providers_tf.exists():
        return "unresolved"
    text = providers_tf.read_text(encoding="utf-8")
    if 'data "digitalocean_ssh_keys" "matching_key"' in text:
        _normalize_digitalocean_sketch_key_references(workspace)
        return "conditional"
    start = text.find('resource "digitalocean_ssh_key" "key"')
    end = text.find('provider "local"', start)
    if start < 0 or end < 0:
        return "unresolved"
    replacement = (
        'data "digitalocean_ssh_keys" "matching_key" {\n'
        "  filter {\n"
        '    key    = "public_key"\n'
        "    values = [chomp(file(local.ssh_pub_key_path))]\n"
        "  }\n"
        "}\n\n"
        'resource "digitalocean_ssh_key" "key" {\n'
        "  count      = length(data.digitalocean_ssh_keys.matching_key.ssh_keys) == 0 ? 1 : 0\n"
        '  name       = "do-key"\n'
        "  public_key = chomp(file(local.ssh_pub_key_path))\n"
        "}\n\n"
        "locals {\n"
        "  sketch_ssh_key_id = length(data.digitalocean_ssh_keys.matching_key.ssh_keys) > 0 ? data.digitalocean_ssh_keys.matching_key.ssh_keys[0].id : digitalocean_ssh_key.key[0].id\n"
        "}\n\n"
    )
    updated = text[:start] + replacement + text[end:]
    if updated != text:
        providers_tf.write_text(updated, encoding="utf-8")
    _normalize_digitalocean_sketch_key_references(workspace)
    return "conditional"


def prepare_digitalocean_borrower_teardown(workspace: Path) -> str:
    """Make an established borrower destroyable after its account key is gone.

    A borrower has no managed account-key resource of its own. Its validated
    retained state contains the non-secret key ID returned by the historical
    lookup. For teardown only, replace that live lookup with the one unambiguous
    cached ID so Terraform can evaluate the retained droplet configuration
    without querying, creating, importing, transferring, or deleting a key.
    """

    providers_tf = workspace / "providers.tf"
    state_file = workspace / "terraform.tfstate"
    if not providers_tf.exists() or not state_file.exists():
        return "unresolved"
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return "unresolved"
    resources = state.get("resources") if isinstance(state, dict) else None
    if not isinstance(resources, list):
        return "unresolved"

    owns_key = any(
        isinstance(resource, dict)
        and resource.get("mode") == "managed"
        and resource.get("type") == "digitalocean_ssh_key"
        and resource.get("name") == "key"
        and bool(resource.get("instances"))
        for resource in resources
    )
    if owns_key:
        return "owner"

    text = providers_tf.read_text(encoding="utf-8")
    static_match = re.search(
        r"# Barragan teardown-only cached borrower key ID\s+locals\s*\{\s*sketch_ssh_key_id\s*=\s*([1-9][0-9]*)\s*\}",
        text,
    )
    matching_resources = [
        resource
        for resource in resources
        if isinstance(resource, dict)
        and resource.get("mode") == "data"
        and resource.get("type") == "digitalocean_ssh_keys"
        and resource.get("name") == "matching_key"
    ]
    key_ids: set[int] = set()
    saw_key_record = False
    invalid_identity = False

    def record_key_id(value: object, *, strict: bool) -> None:
        nonlocal saw_key_record, invalid_identity
        key_id = value.get("id") if isinstance(value, dict) else value
        if isinstance(key_id, bool):
            invalid_identity = invalid_identity or strict
        elif isinstance(key_id, int) and key_id > 0:
            saw_key_record = True
            key_ids.add(key_id)
        elif isinstance(key_id, str) and key_id.isdecimal() and int(key_id) > 0:
            saw_key_record = True
            key_ids.add(int(key_id))
        elif strict:
            invalid_identity = True

    for resource in matching_resources:
        instances = resource.get("instances")
        if not isinstance(instances, list):
            invalid_identity = True
            continue
        for instance in instances:
            attributes = instance.get("attributes") if isinstance(instance, dict) else None
            keys = attributes.get("ssh_keys") if isinstance(attributes, dict) else None
            if not isinstance(keys, list):
                invalid_identity = True
                continue
            for key in keys:
                record_key_id(key, strict=True)

    for resource in resources:
        if not (
            isinstance(resource, dict)
            and resource.get("mode") == "managed"
            and resource.get("type") == "digitalocean_droplet"
        ):
            continue
        for instance in resource.get("instances") or []:
            attributes = instance.get("attributes") if isinstance(instance, dict) else None
            keys = attributes.get("ssh_keys") if isinstance(attributes, dict) else None
            if keys is None:
                continue
            if not isinstance(keys, list):
                invalid_identity = True
                continue
            for key in keys:
                record_key_id(key, strict=True)

    if not saw_key_record and not invalid_identity:
        return "borrower" if static_match else "unresolved"
    if invalid_identity or len(key_ids) != 1:
        raise ValueError("retained DigitalOcean borrower key identity is ambiguous")
    key_id = next(iter(key_ids))

    static_local = f"  sketch_ssh_key_id = {key_id}\n"
    if (
        "# Barragan teardown-only cached borrower key ID" in text
        and static_local in text
        and 'data "digitalocean_ssh_keys" "matching_key"' not in text
    ):
        return "borrower"
    start = text.find('data "digitalocean_ssh_keys" "matching_key"')
    if start < 0:
        start = text.find('resource "digitalocean_ssh_key" "key"')
    end = text.find('provider "local"', start)
    if start < 0 or end < 0:
        raise ValueError("retained DigitalOcean borrower key configuration is unavailable")
    replacement = (
        "# Barragan teardown-only cached borrower key ID\n"
        "locals {\n"
        f"  sketch_ssh_key_id = {key_id}\n"
        "}\n\n"
    )
    providers_tf.write_text(text[:start] + replacement + text[end:], encoding="utf-8")
    return "borrower"


def _normalize_digitalocean_sketch_key_references(workspace: Path) -> None:
    """Use the stable local regardless of whether the key is owned or borrowed."""

    for name in ("middle.tf", "edge.tf"):
        path = workspace / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8")
        updated = text.replace(
            "digitalocean_ssh_key.key.id",
            "local.sketch_ssh_key_id",
        )
        if updated != text:
            path.write_text(updated, encoding="utf-8")


def ensure_linode_firewall_protocol_compatibility(workspace: Path, provider: str) -> list[str]:
    """Normalize legacy Linode firewall protocol values in a copied workspace.

    Current Linode provider validation accepts the protocol enum in uppercase,
    whereas the pinned upstream template still uses lowercase values.  This is
    deliberately a copied-workspace adjustment: Barragan remains compatible
    with upstream without changing its reusable source template.
    """

    if provider != "linode":
        return []
    firewall_tf = workspace / "firewall.tf"
    if not firewall_tf.exists():
        return []
    text = firewall_tf.read_text(encoding="utf-8")
    updated = text
    for legacy, canonical in (("tcp", "TCP"), ("udp", "UDP"), ("icmp", "ICMP")):
        updated = updated.replace(f'protocol = "{legacy}"', f'protocol = "{canonical}"')
    # The legacy template also passes the protocol through dynamic-rule values.
    # Normalize those enum values at the source rather than changing the rule
    # expressions (and therefore preserve the template's rule structure).
    updated = updated.replace(
        'for_each = ["tcp", "udp", "icmp"]',
        'for_each = ["TCP", "UDP", "ICMP"]',
    )
    if updated == text:
        return []
    firewall_tf.write_text(updated, encoding="utf-8")
    return ["firewall.tf"]


def ensure_sketch_firewall_port_list_compatibility(workspace: Path, provider: str) -> list[str]:
    """Type copied legacy sketch firewall port inputs as lists of strings."""

    if provider not in {"linode", "digitalocean"}:
        raise ValueError(f"unsupported sketch provider: {provider}")
    variables_tf = workspace / "variables.tf"
    if not variables_tf.exists():
        return []
    text = variables_tf.read_text(encoding="utf-8")
    updated = text
    for variable_name in ("allowed_tcp_ports", "allowed_udp_ports"):
        updated = _ensure_terraform_variable_type(
            updated,
            variable_name,
            "list(string)",
        )
    if updated == text:
        return []
    variables_tf.write_text(updated, encoding="utf-8")
    return ["variables.tf"]


def ensure_sketch_udp_ingress_compatibility(workspace: Path, provider: str) -> list[str]:
    """Add Barragan's UDP port-list contract to copied legacy sketch templates."""

    if provider not in {"linode", "digitalocean"}:
        raise ValueError(f"unsupported sketch provider: {provider}")
    changed: list[str] = []
    variables_tf = workspace / "variables.tf"
    if variables_tf.exists():
        text = variables_tf.read_text(encoding="utf-8")
        if 'variable "allowed_udp_ports"' not in text:
            variables_tf.write_text(
                text.rstrip() + '\n\nvariable "allowed_udp_ports" {\n  type = list(string)\n  default = []\n}\n',
                encoding="utf-8",
            )
            changed.append("variables.tf")

    if provider == "digitalocean":
        return changed

    firewall_tf = workspace / "firewall.tf"
    if firewall_tf.exists():
        text = firewall_tf.read_text(encoding="utf-8")
        if "var.allowed_udp_ports" not in text:
            marker = '  dynamic "inbound" {\n    // Allow engagement hosts to access each other'
            block = (
                '  dynamic "inbound" {\n'
                '    // Allow Barragan-managed UDP listener ports from provider ingress.\n'
                '    for_each = var.allowed_udp_ports\n'
                '    content {\n'
                '      label    = "allow-udp-${inbound.value}"\n'
                '      action   = "ACCEPT"\n'
                '      protocol = "UDP"\n'
                '      ports    = inbound.value\n'
                '      ipv4     = ["0.0.0.0/0"]\n'
                '    }\n'
                '  }\n\n'
            )
            if marker not in text:
                raise ValueError("legacy Linode firewall engagement-host rule was not found")
            firewall_tf.write_text(text.replace(marker, block + marker, 1), encoding="utf-8")
            changed.append("firewall.tf")
    return changed


def _ensure_terraform_variable_type(text: str, variable_name: str, type_expression: str) -> str:
    declaration = re.search(
        rf'variable\s+"{re.escape(variable_name)}"\s*\{{',
        text,
    )
    if declaration is None:
        return text
    closing_brace = _terraform_block_closing_brace(text, declaration.end() - 1)
    if closing_brace is None:
        return text
    block = text[declaration.start() : closing_brace + 1]
    if re.search(r"\btype\s*=", block):
        return text
    body_start = declaration.end()
    body = text[body_start:closing_brace]
    insertion = f"\n  type = {type_expression}"
    if not body.startswith("\n"):
        insertion += "\n"
    return text[:body_start] + insertion + text[body_start:]


def _terraform_block_closing_brace(text: str, opening_brace: int) -> int | None:
    depth = 0
    quote = ""
    escaped = False
    for index in range(opening_brace, len(text)):
        char = text[index]
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            continue
        if char in {'"', "'"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def disable_legacy_sketch_local_artifacts(workspace: Path) -> list[str]:
    """Disable copied-template SSH/inventory files that Barragan replaces.

    Split applies can give their templatefile calls an empty sibling collection,
    while uniform applies can pass provider-marked objects whose values change
    between plan and apply. Barragan derives the authoritative operator
    artifacts from provider outputs, so these legacy local files must remain
    disabled for every copied workspace regardless of an upstream count guard.
    """

    output_tf = workspace / "output.tf"
    if not output_tf.exists():
        return []
    text = output_tf.read_text(encoding="utf-8")
    updated = text
    for resource in ("ssh_stanza", "ansible_inventory"):
        marker = f'resource "local_file" "{resource}" {{\n'
        start = updated.find(marker)
        if start < 0:
            continue
        next_resource = updated.find('\nresource "', start + len(marker))
        end = len(updated) if next_resource < 0 else next_resource
        block = updated[start:end]
        count_pattern = re.compile(r"(?m)^[ \t]*count[ \t]*=.*$")
        if count_pattern.search(block):
            disabled = count_pattern.sub("  count = 0", block, count=1)
        else:
            disabled = f"{marker}  count = 0\n" + block[len(marker) :]
        updated = updated[:start] + disabled + updated[end:]
    if updated == text:
        return []
    output_tf.write_text(updated, encoding="utf-8")
    return ["output.tf"]
