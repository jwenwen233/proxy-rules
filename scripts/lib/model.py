from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path
import re
from typing import Iterable

import yaml

SUPPORTED_TYPES = {"domain", "domain-suffix", "domain-keyword", "ip-cidr", "ip-asn", "process-name"}
SUPPORTED_TARGETS = frozenset({"shadowrocket", "mihomo"})


class RuleError(ValueError):
    pass


_HOSTNAME_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def normalize_domain(value: object) -> str:
    """Normalize an IDNA hostname and reject rule or URL syntax."""
    if not isinstance(value, str) or not value:
        raise RuleError("invalid domain: value must be a non-empty string")
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value):
        raise RuleError(f"invalid domain: {value}")
    try:
        normalized = value.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as error:
        raise RuleError(f"invalid domain: {value}") from error
    if not normalized or len(normalized.encode("ascii")) > 253:
        raise RuleError(f"invalid domain: {value}")
    labels = normalized.split(".")
    if any(len(label.encode("ascii")) > 63 or not _HOSTNAME_LABEL.fullmatch(label) for label in labels):
        raise RuleError(f"invalid domain: {value}")
    return normalized


@dataclass(frozen=True, slots=True)
class Rule:
    type: str
    value: str
    targets: frozenset[str] = SUPPORTED_TARGETS
    note: str | None = None


def normalize_rule_value(rule_type: str, value: object) -> str:
    """Normalize a canonical rule value and reject output-injection syntax."""
    if not isinstance(value, str) or not value.strip():
        raise RuleError("rule value must be a non-empty string")
    if rule_type in {"domain", "domain-suffix"}:
        return normalize_domain(value)
    if rule_type == "domain-keyword":
        if "," in value or any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise RuleError(f"invalid domain-keyword: {value!r}")
        return value.strip()
    value = value.strip()
    if rule_type == "ip-cidr":
        return str(ip_network(value, strict=False))
    if rule_type == "ip-asn":
        digits = value.upper().removeprefix("AS")
        if not digits.isdigit() or int(digits) <= 0:
            raise RuleError(f"invalid ASN: {value}")
        return digits
    return value


def load_rule_file(path: Path) -> list[Rule]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 1:
        raise RuleError(f"{path}: version must be 1")
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise RuleError(f"{path}: rules must be a list")
    result: list[Rule] = []
    for index, item in enumerate(raw_rules):
        if not isinstance(item, dict):
            raise RuleError(f"{path}:{index}: rule must be a mapping")
        rule_type = item.get("type")
        if rule_type not in SUPPORTED_TYPES:
            raise RuleError(f"{path}:{index}: unsupported rule type: {rule_type}")
        raw_targets = item.get("targets", sorted(SUPPORTED_TARGETS))
        if not isinstance(raw_targets, list) or not raw_targets:
            raise RuleError(f"{path}:{index}: targets must be a non-empty list")
        targets = frozenset(raw_targets)
        if not targets <= SUPPORTED_TARGETS:
            raise RuleError(f"{path}:{index}: unsupported targets: {sorted(targets - SUPPORTED_TARGETS)}")
        if rule_type == "process-name" and targets != frozenset({"mihomo"}):
            raise RuleError("process-name requires targets: [mihomo]")
        result.append(Rule(rule_type, normalize_rule_value(rule_type, item.get("value")), targets, item.get("note")))
    return result


def load_rule_tree(root: Path) -> list[Rule]:
    rules: list[Rule] = []
    for path in sorted(root.rglob("*.yaml")):
        if path.name != "upstreams.yaml":
            rules.extend(load_rule_file(path))
    return rules


def rules_for_target(rules: Iterable[Rule], target: str) -> list[Rule]:
    if target not in SUPPORTED_TARGETS:
        raise RuleError(f"unsupported target: {target}")
    return [rule for rule in rules if target in rule.targets]
