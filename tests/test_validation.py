from pathlib import Path

import pytest

from scripts.lib.model import Rule
from scripts.lib.validation import (
    ValidationError,
    resolve_policy,
    scan_secrets,
    validate_generated_files,
    validate_repository,
    validate_rule_conflicts,
)


def test_detects_direct_reject_conflict():
    errors = validate_rule_conflicts({
        "direct": [Rule("domain-suffix", "example.com")],
        "reject": [Rule("domain-suffix", "example.com")],
    })
    assert errors == ["domain-suffix:example.com appears in direct and reject"]


@pytest.mark.parametrize("secret", [
    "vless:" + "//00000000-0000-0000-0000-000000000000@example.com:443",
    "private" + "Key: abcdefghijklmnopqrstuvwxyz0123456789ABCDE",
    "subscription-" + "userinfo: upload=1; download=2",
])
def test_secret_scanner_rejects_credentials(tmp_path: Path, secret: str):
    (tmp_path / "bad.txt").write_text(secret)
    assert scan_secrets(tmp_path)


def test_readme_plain_protocol_names_are_allowed(tmp_path: Path):
    (tmp_path / "README.md").write_text("Supported protocol names: VLESS, VMess, Trojan.")
    assert scan_secrets(tmp_path) == []


def test_secret_scanner_allows_uuid_shaped_domain_names(tmp_path: Path):
    (tmp_path / "rules.yaml").write_text("domain: 00000000-0000-0000-0000-000000000000.example")
    assert scan_secrets(tmp_path) == []


def test_secret_scanner_rejects_credential_shaped_url_queries(tmp_path: Path):
    (tmp_path / "subscription.txt").write_text("https://example.com/?" + "token=abcdefgh12345678")
    assert scan_secrets(tmp_path)


def test_secret_scanner_skips_its_excluded_directories(tmp_path: Path):
    for directory in (".git", "work", ".cache", ".pytest_cache", "docs/superpowers"):
        path = tmp_path / directory / "credential.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("vless:" + "//00000000-0000-0000-0000-000000000000@example.com:443")
    assert scan_secrets(tmp_path) == []


def test_precedence_routes_required_destinations():
    named_sets = {
        "direct": [Rule("domain-suffix", "scnet.cn")],
        "reject": [Rule("domain-suffix", "ads.example")],
        "ai": [Rule("domain-suffix", "claude.ai"), Rule("domain-suffix", "chatgpt.com")],
    }
    assert resolve_policy("claude.ai", named_sets) == "PRX-AI"
    assert resolve_policy("chatgpt.com", named_sets) == "PRX-AI"
    assert resolve_policy("scnet.cn", named_sets) == "DIRECT"
    assert resolve_policy("192.168.1.1", named_sets) == "DIRECT"
    assert resolve_policy("ads.example", named_sets) == "REJECT"
    assert resolve_policy("example.net", named_sets) == "PRX-Proxy"


def test_generated_file_validator_reports_stale_content(tmp_path: Path):
    sources = {
        "source/personal/direct.yaml": "version: 1\nrules:\n  - {type: domain-suffix, value: example.cn}\n",
        "source/personal/reject.yaml": "version: 1\nrules: []\n",
        "source/ai/anthropic.yaml": "version: 1\nrules: []\n",
        "source/ai/openai.yaml": "version: 1\nrules: []\n",
        "source/ai/openai-voice.yaml": "version: 1\nrules: []\n",
        "source/upstream/reject-domain.yaml": "version: 1\nrules: []\n",
        "source/upstream/media-domain.yaml": "version: 1\nrules: []\n",
        "source/upstream/messaging-domain.yaml": "version: 1\nrules: []\n",
        "source/upstream/apple-microsoft-domain.yaml": "version: 1\nrules: []\n",
        "source/upstream/cn-domain.yaml": "version: 1\nrules: []\n",
        "source/upstream/cn-ip.yaml": "version: 1\nrules: []\n",
    }
    for relative_path, content in sources.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    (tmp_path / "dist/shadowrocket").mkdir(parents=True)
    (tmp_path / "dist/shadowrocket/direct.list").write_text("stale\n")
    assert any("stale generated file: dist/shadowrocket/direct.list" == error
               for error in validate_generated_files(tmp_path))


def test_repository_validator_aggregates_findings_in_order(tmp_path: Path):
    (tmp_path / "credential.txt").write_text("vless:" + "//00000000-0000-0000-0000-000000000000@example.com")
    with pytest.raises(ValidationError) as raised:
        validate_repository(tmp_path)
    findings = str(raised.value).splitlines()
    assert "credential.txt: proxy URI" in findings
    assert any("source/personal/direct.yaml" in finding for finding in findings)
    assert findings == sorted(findings)
