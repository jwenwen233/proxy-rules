from pathlib import Path
import re

import pytest
import yaml

from scripts.lib.model import Rule
from scripts.lib.generate import build_all
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
