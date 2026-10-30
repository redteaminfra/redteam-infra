# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import os
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Protocol


READ_ONLY_COMMANDS = {"namecheap.domains.getList", "namecheap.domains.dns.getHosts"}
NAMECHEAP_API_BASE_URL = "https://api.namecheap.com/xml.response"
NAMECHEAP_DOMAIN_PAGE_SIZE = 100


class NamecheapError(Exception):
    pass


class NamecheapMutationBlockedError(NamecheapError):
    pass


class NamecheapTransport(Protocol):
    def get(self, url: str, timeout: int) -> str:
        ...

    def post(self, url: str, data: dict[str, str], timeout: int) -> str:
        ...


class UrllibNamecheapTransport:
    def get(self, url: str, timeout: int) -> str:
        request = urllib.request.Request(url, method="GET", headers={"Accept": "application/xml"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise NamecheapError(f"Namecheap request failed with HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            reason = str(getattr(exc, "reason", "transport error"))
            raise NamecheapError(f"Namecheap request failed: {_redact_sensitive_text(reason)}") from exc

    def post(self, url: str, data: dict[str, str], timeout: int) -> str:
        encoded = urllib.parse.urlencode(data).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=encoded,
            method="POST",
            headers={"Accept": "application/xml", "Content-Type": "application/x-www-form-urlencoded"},
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise NamecheapError(f"Namecheap request failed with HTTP {exc.code}") from exc
        except urllib.error.URLError as exc:
            reason = str(getattr(exc, "reason", "transport error"))
            raise NamecheapError(f"Namecheap request failed: {_redact_sensitive_text(reason)}") from exc


@dataclass(frozen=True)
class NamecheapDomain:
    name: str
    created: str
    expires: str
    auto_renew: bool
    status: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class NamecheapHost:
    name: str
    record_type: str
    address: str
    ttl: str
    mx_pref: str
    host_id: str = ""

    def to_dict(self) -> dict[str, str]:
        body = {
            "name": self.name,
            "type": self.record_type,
            "address": self.address,
            "ttl": self.ttl,
            "mxPref": self.mx_pref,
        }
        if self.host_id:
            body["hostId"] = self.host_id
        return body


class NamecheapReadOnlyClient:
    def __init__(
        self,
        username: str,
        api_key: str,
        *,
        client_ip: str | None = None,
        base_url: str = NAMECHEAP_API_BASE_URL,
        timeout: int = 30,
        transport: NamecheapTransport | None = None,
    ):
        self.username = username
        self.api_key = api_key
        self.client_ip = client_ip or os.environ.get("BARRAGAN_NAMECHEAP_CLIENT_IP", "127.0.0.1")
        self.base_url = base_url
        self.timeout = timeout
        self.transport = transport or UrllibNamecheapTransport()

    def get_domains(self) -> list[NamecheapDomain]:
        domains: list[NamecheapDomain] = []
        page = 1

        while True:
            payload = self.request(
                "namecheap.domains.getList",
                {"Page": str(page), "PageSize": str(NAMECHEAP_DOMAIN_PAGE_SIZE)},
            )
            root = _parse_xml(payload)
            page_domains = [_domain_from_node(node) for node in root.findall(".//{*}Domain") if _attr(node, "Name")]
            domains.extend(page_domains)

            paging = _paging(root)
            total_items = paging.get("total_items")
            effective_page_size = paging.get("page_size") or NAMECHEAP_DOMAIN_PAGE_SIZE
            current_page = paging.get("current_page") or page
            if total_items is not None and len(domains) >= total_items:
                break
            if len(page_domains) < effective_page_size:
                break
            page = max(page + 1, current_page + 1)

        return domains

    def get_hosts(self, domain_name: str) -> list[NamecheapHost]:
        sld, tld = _split_domain(domain_name)
        payload = self.request("namecheap.domains.dns.getHosts", {"SLD": sld, "TLD": tld})
        root = _parse_xml(payload)
        return [
            NamecheapHost(
                name=_attr(node, "Name"),
                record_type=_attr(node, "Type"),
                address=_attr(node, "Address"),
                ttl=_attr(node, "TTL"),
                mx_pref=_attr(node, "MXPref"),
                host_id=_attr_any(node, "HostId", "HostID"),
            )
            for node in _find_elements(root, "host")
        ]

    def request(self, command: str, params: dict[str, str] | None = None) -> str:
        if command not in READ_ONLY_COMMANDS:
            raise NamecheapMutationBlockedError(f"Namecheap command is blocked by Barragan read-only policy: {command}")
        return _request_namecheap_xml(
            username=self.username,
            api_key=self.api_key,
            client_ip=self.client_ip,
            base_url=self.base_url,
            timeout=self.timeout,
            transport=self.transport,
            command=command,
            params=params,
        )


class NamecheapDnsClient(NamecheapReadOnlyClient):
    def set_hosts(self, domain_name: str, hosts: list[NamecheapHost]) -> bool:
        sld, tld = _split_domain(domain_name)
        params: dict[str, str] = {"SLD": sld, "TLD": tld}
        for index, host in enumerate(hosts, start=1):
            params[f"HostName{index}"] = host.name
            params[f"RecordType{index}"] = host.record_type
            params[f"Address{index}"] = host.address
            if host.mx_pref:
                params[f"MXPref{index}"] = host.mx_pref
            if host.ttl:
                params[f"TTL{index}"] = host.ttl
        payload = _request_namecheap_xml(
            username=self.username,
            api_key=self.api_key,
            client_ip=self.client_ip,
            base_url=self.base_url,
            timeout=self.timeout,
            transport=self.transport,
            command="namecheap.domains.dns.setHosts",
            params=params,
            method="POST",
        )
        root = _parse_xml(payload)
        result = next(iter(_find_elements(root, "DomainDNSSetHostsResult")), None)
        if result is None:
            raise NamecheapError("Namecheap setHosts response did not include a result")
        return _bool_attr(result, "IsSuccess")


def parse_namecheap_secret(secret: str) -> tuple[str, str]:
    if ":" not in secret:
        raise NamecheapError("Namecheap credential secret must use username:apikey")
    username, api_key = secret.split(":", 1)
    username = username.strip()
    api_key = api_key.strip()
    if not username or not api_key:
        raise NamecheapError("Namecheap credential secret must include both username and API key")
    return username, api_key


def _split_domain(domain_name: str) -> tuple[str, str]:
    parts = domain_name.strip(".").split(".")
    if len(parts) < 2:
        raise NamecheapError("domain name must include SLD and TLD")
    return ".".join(parts[:-1]), parts[-1]


def _parse_xml(payload: str) -> ET.Element:
    try:
        return ET.fromstring(payload)
    except ET.ParseError as exc:
        raise NamecheapError("Namecheap returned invalid XML") from exc


def _raise_for_namecheap_errors(payload: str) -> None:
    root = _parse_xml(payload)
    errors = [str(node.text or "").strip() for node in root.findall(".//{*}Error") if str(node.text or "").strip()]
    if errors:
        raise NamecheapError(f"Namecheap request failed: {'; '.join(_redact_sensitive_text(error) for error in errors)}")


def _request_namecheap_xml(
    *,
    username: str,
    api_key: str,
    client_ip: str,
    base_url: str,
    timeout: int,
    transport: NamecheapTransport,
    command: str,
    params: dict[str, str] | None = None,
    method: str = "GET",
) -> str:
    query = {
        "ApiUser": username,
        "ApiKey": api_key,
        "UserName": username,
        "Command": command,
        "ClientIp": client_ip,
    }
    query.update(params or {})
    method = method.upper()
    if method == "GET":
        url = f"{base_url}?{urllib.parse.urlencode(query)}"
    elif method == "POST":
        url = base_url
    else:
        raise NamecheapError(f"unsupported Namecheap request method: {method}")
    try:
        payload = transport.post(url, query, timeout) if method == "POST" else transport.get(url, timeout)
    except NamecheapError:
        raise
    except Exception as exc:
        raise NamecheapError(f"Namecheap request failed: {_redact_sensitive_text(str(exc))}") from exc
    _raise_for_namecheap_errors(payload)
    return payload


def _domain_from_node(node: ET.Element) -> NamecheapDomain:
    metadata: dict[str, Any] = {
        "isLocked": _bool_attr(node, "IsLocked"),
        "whoisGuard": _attr(node, "WhoisGuard"),
        "user": _attr(node, "User"),
    }
    if _attr(node, "ID"):
        metadata["namecheapId"] = _attr(node, "ID")
    if _has_attr(node, "IsPremium"):
        metadata["isPremium"] = _bool_attr(node, "IsPremium")
    if _has_attr(node, "IsOurDNS"):
        metadata["isOurDNS"] = _bool_attr(node, "IsOurDNS")
    return NamecheapDomain(
        name=_attr(node, "Name"),
        created=_attr(node, "Created"),
        expires=_attr(node, "Expires"),
        auto_renew=_bool_attr(node, "AutoRenew"),
        status="expired" if _bool_attr(node, "IsExpired") else "active",
        metadata=metadata,
    )


def _paging(root: ET.Element) -> dict[str, int | None]:
    node = root.find(".//{*}Paging")
    if node is None:
        return {"total_items": None, "current_page": None, "page_size": None}
    return {
        "total_items": _int_child_text(node, "TotalItems"),
        "current_page": _int_child_text(node, "CurrentPage"),
        "page_size": _int_child_text(node, "PageSize"),
    }


def _int_child_text(node: ET.Element, child_name: str) -> int | None:
    child = node.find(f"{{*}}{child_name}")
    if child is None or child.text is None:
        return None
    try:
        value = int(str(child.text).strip())
    except ValueError:
        return None
    return value if value > 0 else None


def _find_elements(root: ET.Element, local_name: str) -> list[ET.Element]:
    expected = local_name.lower()
    return [node for node in root.iter() if _local_name(node.tag).lower() == expected]


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _attr(node: ET.Element, key: str) -> str:
    return str(node.attrib.get(key, "")).strip()


def _attr_any(node: ET.Element, *keys: str) -> str:
    for key in keys:
        value = _attr(node, key)
        if value:
            return value
    return ""


def _has_attr(node: ET.Element, key: str) -> bool:
    return key in node.attrib


def _bool_attr(node: ET.Element, key: str) -> bool:
    return _attr(node, key).lower() in {"true", "yes", "1"}


def _redact_sensitive_text(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.query:
        return value.replace(urllib.parse.urlunsplit(parsed), "[redacted-namecheap-url]")
    for marker in ("ApiKey", "apikey", "api_key", "secret", "token", "password"):
        if marker in value:
            return "redacted sensitive Namecheap error"
    return value
