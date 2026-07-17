import json
from pathlib import Path

import pytest

from scripts.lib.model import RuleError, load_rule_file, rules_for_target


def write_rules(tmp_path: Path, body: str) -> Path:
    path = tmp_path / "rules.yaml"
    path.write_text(body, encoding="utf-8")
    return path


def test_loads_and_normalizes_rules(tmp_path: Path) -> None:
    path = write_rules(tmp_path, """
version: 1
rules:
  - type: domain-suffix
    value: Example.COM.
  - type: ip-cidr
    value: 160.79.104.1/21
  - type: process-name
    value: ToDesk
    targets: [mihomo]
""")
    rules = load_rule_file(path)
    assert [(rule.type, rule.value) for rule in rules] == [
        ("domain-suffix", "example.com"),
        ("ip-cidr", "160.79.104.0/21"),
        ("process-name", "ToDesk"),
    ]
    assert [rule.value for rule in rules_for_target(rules, "shadowrocket")] == [
        "example.com", "160.79.104.0/21",
    ]


@pytest.mark.parametrize("rule_type", ["unknown", "domain-wildcard"])
def test_rejects_unknown_types(tmp_path: Path, rule_type: str) -> None:
    path = write_rules(tmp_path, f"version: 1\nrules:\n  - type: {rule_type}\n    value: example.com\n")
    with pytest.raises(RuleError, match="unsupported rule type"):
        load_rule_file(path)


def test_rejects_process_name_without_mihomo_target(tmp_path: Path) -> None:
    path = write_rules(tmp_path, "version: 1\nrules:\n  - type: process-name\n    value: ToDesk\n")
    with pytest.raises(RuleError, match="process-name requires targets"):
        load_rule_file(path)


@pytest.mark.parametrize("value", ["https://example.com", "bad domain", "example.com,REJECT"])
def test_curated_loader_rejects_non_hostname_domain_syntax(tmp_path: Path, value: str) -> None:
    path = write_rules(tmp_path, f"version: 1\nrules:\n  - type: domain\n    value: {value}\n")
    with pytest.raises(RuleError, match="invalid domain"):
        load_rule_file(path)


def test_domain_normalization_uses_idna(tmp_path: Path) -> None:
    path = write_rules(tmp_path, """
version: 1
rules:
  - type: domain-suffix
    value: B\u00fccher.Example.
""")
    rules = load_rule_file(path)
    assert [(rule.type, rule.value) for rule in rules] == [
        ("domain-suffix", "xn--bcher-kva.example"),
    ]


@pytest.mark.parametrize("value", ["keyword,REJECT", "keyword\nREJECT", "keyword\x01REJECT"])
def test_loader_rejects_domain_keyword_injection_characters(tmp_path: Path, value: str) -> None:
    path = write_rules(
        tmp_path,
        "version: 1\nrules:\n  - type: domain-keyword\n    value: " + json.dumps(value) + "\n",
    )

    with pytest.raises(RuleError, match="invalid domain-keyword"):
        load_rule_file(path)
