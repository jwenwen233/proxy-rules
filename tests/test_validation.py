from pathlib import Path
import re
import hashlib
import json

import pytest
import yaml

from scripts.lib.model import Rule
from scripts.lib.generate import build_all
from scripts.lib.validation import (
    ValidationError,
    resolve_policy,
    scan_secrets,
    validate_upstream_lock,
    validate_generated_files,
    validate_repository,
    validate_rule_conflicts,
)


def _write_valid_upstream_lock(root: Path) -> tuple[Path, Path]:
    snapshot = root / "source/upstream/domains.yaml"
    snapshot.parent.mkdir(parents=True, exist_ok=True)
    snapshot.write_text("version: 1\nrules:\n- type: domain\n  value: example.com\n", encoding="utf-8")
    raw_hash = "a" * 64
    normalized_hash = hashlib.sha256(snapshot.read_bytes()).hexdigest()
    (root / "source/upstreams.yaml").write_text("""
version: 1
sets:
  domains:
    parser: domain-yaml
    output: source/upstream/domains.yaml
    urls: [https://example.test/domains.yaml]
""", encoding="utf-8")
    (root / "source/upstream.lock.json").write_text(json.dumps({"version": 1, "sets": {
        "domains": {
            "url": "https://example.test/domains.yaml",
            "retrieved_at": "2026-07-17T12:54:37Z",
            "raw_sha256": raw_hash,
            "normalized_sha256": normalized_hash,
        },
    }}), encoding="utf-8")
    return snapshot, root / "source/upstream.lock.json"


def test_upstream_lock_validator_accepts_valid_offline_snapshot(tmp_path: Path) -> None:
    _write_valid_upstream_lock(tmp_path)
    assert validate_upstream_lock(tmp_path) == []


@pytest.mark.parametrize("tamper", ["snapshot", "set", "url", "timestamp"])
def test_upstream_lock_validator_rejects_tampering(tmp_path: Path, tamper: str) -> None:
    snapshot, lock_path = _write_valid_upstream_lock(tmp_path)
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if tamper == "snapshot":
        snapshot.write_text("tampered\n", encoding="utf-8")
    elif tamper == "set":
        lock["sets"]["extra"] = lock["sets"]["domains"]
    elif tamper == "url":
        lock["sets"]["domains"]["url"] = "https://example.test/other.yaml"
    else:
        lock["sets"]["domains"].pop("retrieved_at")
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    assert validate_upstream_lock(tmp_path)


def test_upstream_lock_validator_rejects_invalid_timestamp_and_hash(tmp_path: Path) -> None:
    _, lock_path = _write_valid_upstream_lock(tmp_path)
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["sets"]["domains"]["retrieved_at"] = "not-a-date"
    lock["sets"]["domains"]["raw_sha256"] = "not-a-hash"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    errors = validate_upstream_lock(tmp_path)
    assert any("retrieved_at" in error for error in errors)
    assert any("raw_sha256" in error for error in errors)


def test_upstream_lock_validator_rejects_malformed_manifest_and_lock_metadata(tmp_path: Path) -> None:
    _, lock_path = _write_valid_upstream_lock(tmp_path)
    manifest_path = tmp_path / "source/upstreams.yaml"
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    manifest["sets"]["domains"]["parser"] = "unknown"
    manifest["extra"] = True
    lock["extra"] = True
    manifest_path.write_text(yaml.safe_dump(manifest), encoding="utf-8")
    lock_path.write_text(json.dumps(lock), encoding="utf-8")

    errors = validate_upstream_lock(tmp_path)

    assert any("malformed upstream manifest" in error for error in errors)
    assert any("malformed upstream lock" in error for error in errors)
    assert any("unsupported upstream parser" in error for error in errors)


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


@pytest.mark.parametrize("secret", [
    "pass" + "word: abc",
    "Private-" + "Key: abc",
    "?" + "token=abc",
])
def test_secret_scanner_rejects_short_non_empty_credentials(tmp_path: Path, secret: str):
    (tmp_path / "short-credential.txt").write_text(secret)
    assert scan_secrets(tmp_path)


@pytest.mark.parametrize("control", (b"\x01", b"\x7f"))
def test_secret_scanner_skips_binary_files_with_secret_shaped_ascii(tmp_path: Path, control: bytes):
    (tmp_path / "binary.dat").write_bytes(control + b"pass" + b"word: abc")
    assert scan_secrets(tmp_path) == []


def test_secret_scanner_skips_its_excluded_directories(tmp_path: Path):
    for directory in (".git", ".superpowers", "work", ".cache", ".pytest_cache", "docs/superpowers"):
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


def test_precedence_routes_critical_ai_dependencies_before_reject():
    destination = "o33249.ingest.sentry.io"
    named_sets = {
        "reject": [Rule("domain", destination)],
        "ai": [Rule("domain", destination)],
    }
    assert resolve_policy(destination, named_sets) == "PRX-AI"


def _write_generated_outputs(root: Path) -> dict[Path, str]:
    expected = build_all(root)
    for path, content in expected.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return expected


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


def test_generated_file_validator_reports_invalid_utf8(tmp_path: Path):
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
    _write_generated_outputs(tmp_path)
    (tmp_path / "dist/shadowrocket/direct.list").write_bytes(b"\xff")

    assert "cannot read generated file: dist/shadowrocket/direct.list" in validate_generated_files(tmp_path)


def test_repository_validator_aggregates_findings_in_order(tmp_path: Path):
    (tmp_path / "credential.txt").write_text("vless:" + "//00000000-0000-0000-0000-000000000000@example.com")
    with pytest.raises(ValidationError) as raised:
        validate_repository(tmp_path)
    findings = str(raised.value).splitlines()
    assert "credential.txt: proxy URI" in findings
    assert any("source/personal/direct.yaml" in finding for finding in findings)
    assert findings == sorted(findings)


def test_readme_has_operating_sections():
    repo_root = Path(__file__).parents[1]
    text = (repo_root / "README.md").read_text(encoding="utf-8")
    required = [
        "## Shadowrocket 安装",
        "## Clash Verge Rev 安装",
        "## 更换机场",
        "## DNS 检测结果怎么读",
        "## WebRTC 检测结果怎么读",
        "## 回滚",
        "python3 scripts/build_rules.py --check",
        "python3 scripts/validate.py",
    ]
    assert all(item in text for item in required)


def test_readme_documents_exact_upstream_provenance():
    text = (Path(__file__).parents[1] / "README.md").read_text(encoding="utf-8")
    required = [
        "https://github.com/MetaCubeX/meta-rules-dat",
        "GPL-3.0",
        "source/upstreams.yaml",
        "source/upstream.lock.json",
        "https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps",
        "https://openai.com/chatgpt-voice.json",
        "https://ip.net.coffee/claude/site.html",
        "community/manual reference",
        "https://www.anthropic.com/",
        "https://github.com/MetaCubeX/mihomo",
        "https://github.com/clash-verge-rev/clash-verge-rev",
        "https://github.com/h2y/Shadowrocket-ADBlock-Rules/wiki",
    ]
    assert all(item in text for item in required)


def test_license_is_unmodified_gpl_v3_text():
    text = (Path(__file__).parents[1] / "LICENSE").read_text(encoding="utf-8")
    assert text.startswith("                    GNU GENERAL PUBLIC LICENSE\n")
    assert "Version 3, 29 June 2007" in text
    assert text.rstrip().endswith("<https://www.gnu.org/licenses/why-not-lgpl.html>.")


def test_validation_workflow_is_pinned_least_privilege_and_reproducible():
    text = (Path(__file__).parents[1] / ".github/workflows/validate.yml").read_text(
        encoding="utf-8"
    )
    workflow = yaml.safe_load(text)
    triggers = workflow.get("on", workflow.get(True))  # PyYAML 1.1 parses `on` as True.

    assert {"push", "pull_request", "schedule"} <= set(triggers)
    assert triggers["schedule"] == [{"cron": "17 3 * * *"}]
    assert workflow["permissions"] == {"contents": "read"}

    jobs = workflow["jobs"]
    scheduled = jobs["scheduled-update"]
    assert scheduled["permissions"] == {
        "contents": "write",
        "pull-requests": "write",
    }
    assert all("permissions" not in job for name, job in jobs.items() if name != "scheduled-update")
    for job in jobs.values():
        checkout = next(step for step in job["steps"] if step.get("uses", "").startswith("actions/checkout@"))
        assert checkout["with"] == {"persist-credentials": False}

    expected_actions = {
        "actions/checkout": "34e114876b0b11c390a56381ad16ebd13914f8d5",
        "actions/setup-python": "a26af69be951a213d495a4c3e4e4022e16d87065",
        "actions/setup-node": "49933ea5288caeca8642d1e84afbd3f7d6820020",
        "peter-evans/create-pull-request": "22a9089034f40e5a961c8808d113e2c98fb63676",
    }
    for action, sha in expected_actions.items():
        assert f"uses: {action}@{sha}" in text
    assert all(re.fullmatch(r"[\w./-]+@[0-9a-f]{40}(?:\s+#.*)?", value.strip())
               for value in re.findall(r"^\s*uses:\s*(.+)$", text, re.MULTILINE))

    assert "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.28/mihomo-linux-amd64-compatible-v1.19.28.gz" in text
    assert "70d01cfb8cb7bf7a92fd1af16cb4b9553d90bb4eecde3b5c4849103e27c80ddb" in text
    for command in (
        "python -m pip install -e '.[dev]'",
        "pytest -q",
        "node --test tests/test_clash_script.cjs",
        "python scripts/build_rules.py --check",
        "python scripts/validate.py",
        "python scripts/sync_upstreams.py --update",
        "gzip -dc .cache/mihomo.gz > .cache/mihomo",
        ".cache/mihomo -t -f .cache/test-config.yaml",
    ):
        assert command in text
    create_pr = next(step["with"] for step in scheduled["steps"]
                     if step.get("uses", "").startswith("peter-evans/create-pull-request@"))
    assert "python scripts/build_rules.py" in [step.get("run") for step in scheduled["steps"]]
    assert create_pr["branch"] == "automation/update-rules"
    assert create_pr["title"] == "chore: update upstream rules"
