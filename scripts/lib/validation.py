from __future__ import annotations

from collections.abc import Iterable, Iterator
from ipaddress import ip_address, ip_network
import os
from pathlib import Path
import re

import yaml

from scripts.build_rules import generated_files
from scripts.lib.generate import build_all
from scripts.lib.model import Rule, RuleError, load_rule_file


POLICIES = {
    "DIRECT", "REJECT", "PRX-Manual", "PRX-Auto", "PRX-AI",
    "PRX-Media", "PRX-Messaging", "PRX-Apple-Microsoft", "PRX-Proxy",
}

SET_POLICIES = {
    "direct": "DIRECT",
    "reject": "REJECT",
    "ai": "PRX-AI",
    "messaging": "PRX-Messaging",
    "media": "PRX-Media",
    "apple-microsoft": "PRX-Apple-Microsoft",
    "cn-domain": "DIRECT",
    "cn-ip": "DIRECT",
    "proxy": "PRX-Proxy",
}

SOURCE_SETS = {
    "direct": ("source/personal/direct.yaml",),
    "reject": ("source/personal/reject.yaml", "source/upstream/reject-domain.yaml"),
    "ai": ("source/ai/anthropic.yaml", "source/ai/openai.yaml", "source/ai/openai-voice.yaml"),
    "messaging": ("source/upstream/messaging-domain.yaml",),
    "media": ("source/upstream/media-domain.yaml",),
    "apple-microsoft": ("source/upstream/apple-microsoft-domain.yaml",),
    "cn-domain": ("source/upstream/cn-domain.yaml",),
    "cn-ip": ("source/upstream/cn-ip.yaml",),
    "proxy": ("source/personal/proxy.yaml",),
}

PRECEDENCE = (
    "direct", "reject", "ai", "messaging", "media", "apple-microsoft", "cn-domain", "cn-ip",
)

_EXCLUDED_DIRECTORY_NAMES = {".git", "work", ".cache", ".pytest_cache"}
_PLACEHOLDER_URL = re.compile(
    r"https?://[^\s\"']*(?:\{(?:owner|repo|branch)\}|<(?:owner|repo|branch)>|"
    r"your_(?:username|repo|branch)|owner/repository)[^\s\"']*",
    re.IGNORECASE,
)
_UUID_FIELD = re.compile(
    r"\b(?:uuid|client[-_ ]?id)\s*[:=]\s*[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\b",
    re.IGNORECASE,
)
_PRIVATE_KEY = re.compile(
    r"\b(?:private[-_ ]?key|reality[-_ ]?(?:private[-_ ]?)?key)\s*[:=]\s*[^\s#]{8,}",
    re.IGNORECASE,
)
_PASSWORD = re.compile(r"\b(?:password|passwd)\s*[:=]\s*[^\s#]{8,}", re.IGNORECASE)
_SUBSCRIPTION_USERINFO = re.compile("subscription" + r"[_-]?" + r"userinfo\s*:", re.IGNORECASE)
_SUBSCRIPTION_QUERY = re.compile(
    r"[?&](?:token|key|uuid|password|secret|auth)=[^\s&#]{8,}",
    re.IGNORECASE,
)
_PROXY_PREFIXES = tuple(scheme + ":" + r"//" for scheme in (
    "vless", "vmess", "trojan", "ss", "ssr", "hysteria", "hysteria2", "tuic", "shadowsocks",
))


class ValidationError(ValueError):
    """Raised when repository validation finds one or more safety failures."""


def validate_rule_conflicts(named_sets: dict[str, list[Rule]]) -> list[str]:
    """Return deterministic duplicate and unsafe direct/reject overlap findings."""
    errors: list[str] = []
    locations: dict[tuple[str, str], list[str]] = {}
    for name in sorted(named_sets):
        seen: set[tuple[str, str]] = set()
        for rule in named_sets[name]:
            key = (rule.type, rule.value)
            if key in seen:
                errors.append(f"duplicate {rule.type}:{rule.value} in {name}")
            else:
                seen.add(key)
            locations.setdefault(key, []).append(name)

    for (rule_type, value), names in sorted(locations.items()):
        unique_names = sorted(set(names))
        if "direct" in unique_names and "reject" in unique_names:
            errors.append(f"{rule_type}:{value} appears in direct and reject")
    return sorted(set(errors))


def validate_policy_references(policy_references: Iterable[str]) -> list[str]:
    return [f"unknown policy: {policy}" for policy in sorted(set(policy_references) - POLICIES)]


def _is_private_destination(destination: str) -> bool:
    try:
        address = ip_address(destination)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local or address.is_unspecified


def _rule_matches(destination: str, rule: Rule) -> bool:
    if rule.type == "ip-cidr":
        try:
            return ip_address(destination) in ip_network(rule.value, strict=False)
        except ValueError:
            return False
    if rule.type == "ip-asn" or rule.type == "process-name":
        return False
    try:
        ip_address(destination)
        return False
    except ValueError:
        pass
    domain = destination.rstrip(".").lower()
    value = rule.value.rstrip(".").lower()
    if rule.type == "domain":
        return domain == value
    if rule.type == "domain-suffix":
        return domain == value or domain.endswith("." + value)
    if rule.type == "domain-keyword":
        return value in domain
    return False


def resolve_policy(destination: str, named_sets: dict[str, list[Rule]]) -> str:
    """Resolve a destination according to the documented, safe rule precedence."""
    if _is_private_destination(destination):
        return "DIRECT"
    for name in PRECEDENCE:
        if any(_rule_matches(destination, rule) for rule in named_sets.get(name, [])):
            return SET_POLICIES[name]
    return "PRX-Proxy"


def _is_excluded_directory(root: Path, current: Path, child: str) -> bool:
    if child in _EXCLUDED_DIRECTORY_NAMES:
        return True
    return current == root / "docs" and child == "superpowers"


def _iter_scannable_files(root: Path) -> Iterator[Path]:
    for directory, directories, filenames in os.walk(root):
        current = Path(directory)
        directories[:] = sorted(
            child for child in directories if not _is_excluded_directory(root, current, child)
        )
        for filename in sorted(filenames):
            yield current / filename


def _secret_kinds(text: str) -> list[str]:
    findings: list[str] = []
    if any(prefix in text.lower() for prefix in _PROXY_PREFIXES):
        findings.append("proxy URI")
    if _UUID_FIELD.search(text):
        findings.append("UUID credential")
    if _PRIVATE_KEY.search(text):
        findings.append("private or Reality key")
    if _PASSWORD.search(text):
        findings.append("password")
    if _SUBSCRIPTION_USERINFO.search(text):
        findings.append("subscription user info")
    if _SUBSCRIPTION_QUERY.search(text):
        findings.append("subscription credential query")
    return findings


def scan_secrets(root: Path) -> list[str]:
    """Find credentials in tracked content while skipping local and generated work areas."""
    root = root.resolve()
    errors: list[str] = []
    for path in _iter_scannable_files(root):
        try:
            raw = path.read_bytes()
        except OSError as error:
            errors.append(f"cannot scan {path.relative_to(root).as_posix()}: {error}")
            continue
        if b"\0" in raw:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        relative_path = path.relative_to(root).as_posix()
        errors.extend(f"{relative_path}: {kind}" for kind in _secret_kinds(text))
    return sorted(errors)


def _load_named_sets(root: Path) -> tuple[dict[str, list[Rule]], list[str]]:
    named_sets: dict[str, list[Rule]] = {}
    errors: list[str] = []
    for name, source_paths in SOURCE_SETS.items():
        rules: list[Rule] = []
        for relative_path in source_paths:
            path = root / relative_path
            try:
                rules.extend(load_rule_file(path))
            except (OSError, RuleError, yaml.YAMLError) as error:
                errors.append(f"{relative_path}: {error}")
        named_sets[name] = rules
    return named_sets, errors


def _validate_raw_rule_files(root: Path) -> list[str]:
    errors: list[str] = []
    for path in sorted((root / "source").rglob("*.yaml")):
        if path.name == "upstreams.yaml":
            continue
        relative_path = path.relative_to(root).as_posix()
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as error:
            errors.append(f"{relative_path}: {error}")
            continue
        rules = data.get("rules") if isinstance(data, dict) else None
        if not isinstance(rules, list):
            continue
        for index, item in enumerate(rules):
            if not isinstance(item, dict):
                continue
            rule_type = item.get("type")
            value = item.get("value")
            if rule_type == "domain-keyword" and not str(item.get("note") or "").strip():
                errors.append(f"{relative_path}:{index}: domain-keyword requires a non-empty note")
            if rule_type == "ip-cidr" and isinstance(value, str):
                try:
                    normalized = str(ip_network(value, strict=False))
                except ValueError:
                    continue
                if value != normalized:
                    errors.append(f"{relative_path}:{index}: non-normalized IP: {value}")
    return errors


def _is_empty_output(path: Path, content: str) -> bool:
    if not content.strip():
        return True
    if path.suffix != ".yaml":
        return False
    try:
        payload = yaml.safe_load(content)
    except yaml.YAMLError:
        return False
    return isinstance(payload, dict) and payload.get("payload") == []


def validate_generated_files(root: Path) -> list[str]:
    """Ensure all generated files are present, non-empty, and match canonical sources."""
    root = root.resolve()
    try:
        expected = build_all(root)
    except (OSError, RuleError, yaml.YAMLError) as error:
        return [f"cannot build generated files: {error}"]

    errors: list[str] = []
    actual = generated_files(root)
    for path in sorted(expected):
        relative_path = path.relative_to(root).as_posix()
        content = expected[path]
        if _is_empty_output(path, content):
            errors.append(f"empty required output: {relative_path}")
        if not path.exists():
            errors.append(f"missing generated file: {relative_path}")
        elif path.read_text(encoding="utf-8") != content:
            errors.append(f"stale generated file: {relative_path}")
    for path in sorted(actual - set(expected)):
        errors.append(f"stale generated file: {path.relative_to(root).as_posix()}")
    return sorted(errors)


def _validate_repository_urls(root: Path) -> list[str]:
    errors: list[str] = []
    for path in _iter_scannable_files(root):
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\0" in raw:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _PLACEHOLDER_URL.search(text):
            errors.append(f"unresolved repository URL placeholder: {path.relative_to(root).as_posix()}")
    return sorted(errors)


def validate_repository(root: Path) -> None:
    """Raise one ValidationError containing every deterministic repository finding."""
    root = root.resolve()
    named_sets, load_errors = _load_named_sets(root)
    errors = [
        *load_errors,
        *validate_rule_conflicts(named_sets),
        *validate_policy_references(SET_POLICIES.values()),
        *_validate_raw_rule_files(root),
        *validate_generated_files(root),
        *_validate_repository_urls(root),
        *scan_secrets(root),
    ]
    if errors:
        raise ValidationError("\n".join(sorted(set(errors))))
