# Personal Proxy Rules Repository Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a public, reproducible rules repository that applies one personal routing and strict-DNS policy to separately imported Shadowrocket and Clash Verge Rev/Mihomo subscriptions.

**Architecture:** Curated rules and normalized, tracked upstream snapshots form the canonical source. Python generates deterministic Shadowrocket and Mihomo outputs and validates rules, DNS settings, precedence, and secrets. A static Shadowrocket configuration and a Clash Verge global JavaScript enhancement consume those outputs while preserving locally imported node credentials.

**Tech Stack:** Python 3.11+, PyYAML 6.x, pytest 8.x, Node.js 18+ built-in test runner, Clash Verge Rev/Mihomo, Shadowrocket, GitHub Actions.

## Global Constraints

- Public repository target: `https://github.com/jwenwen233/proxy-rules`.
- Never track proxy nodes, subscription URLs, UUIDs, Reality keys, passwords, or provider account details.
- Route China and private traffic directly; route unknown non-China traffic through `PRX-Proxy`; reject maintained advertising and malicious destinations.
- Route Claude, Anthropic, ChatGPT, OpenAI, and ChatGPT Voice through `PRX-AI`, which has no `DIRECT` choice.
- Disable IPv6 in both clients.
- Preserve UDP; when a Shadowrocket node cannot carry UDP, use `REJECT`, never silent direct fallback.
- Ordinary DNS uses Cloudflare DoH through the selected proxy with no system fallback.
- Direct encrypted DNS is allowed only to bootstrap proxy-server hostnames before a tunnel exists.
- Preserve non-reserved airport nodes, proxy providers, policy groups, ports, and runtime fields.
- Use stable reserved prefixes `PRX-` for generated policy groups and rule providers.
- License repository-authored and incorporated GPL-compatible outputs under GPL-3.0 with upstream attribution.
- Do not modify or add the existing untracked `work/` directory.

---

## File Map

- `pyproject.toml`: Python version, runtime dependency, pytest configuration.
- `.gitignore`: Python caches, test caches, temporary upstream downloads, and local client exports.
- `scripts/lib/model.py`: canonical `Rule` model, YAML loading, normalization, and target filtering.
- `scripts/lib/upstream.py`: network retrieval, upstream parsing, atomic snapshot and lock updates.
- `scripts/lib/generate.py`: deterministic Shadowrocket and Mihomo rendering.
- `scripts/lib/validation.py`: conflict, policy, DNS, generated-file, and secret checks.
- `scripts/sync_upstreams.py`: explicit upstream update/check CLI.
- `scripts/build_rules.py`: offline generated-output CLI.
- `scripts/validate.py`: repository-wide validation CLI.
- `source/upstreams.yaml`: exact upstream URLs, parser type, destination snapshot, and behavior.
- `source/upstream/`: tracked normalized snapshots used by ordinary builds.
- `source/personal/*.yaml`: personal direct, proxy, and reject additions.
- `source/ai/*.yaml`: official and supplemental AI rules plus normalized voice IP snapshot.
- `dist/shadowrocket/*.list`: generated Shadowrocket rule sets.
- `dist/mihomo/*.yaml`: generated Mihomo rule-provider payloads.
- `configs/shadowrocket.conf`: node-free Shadowrocket policy, DNS, and rule configuration.
- `configs/clash-verge-script.js`: node-free Clash Verge global enhancement script.
- `tests/fixtures/airport.json`: representative profile containing inline nodes, a proxy provider, an existing group, DNS fallback, and existing rules; JSON is also valid YAML for Mihomo validation.
- `tests/test_model.py`: canonical parsing and normalization tests.
- `tests/test_upstream.py`: upstream parsing, locking, failure, and atomicity tests.
- `tests/test_generation.py`: exact client output and deterministic-build tests.
- `tests/test_validation.py`: conflict, precedence, DNS, and secret scanning tests.
- `tests/test_shadowrocket.py`: Shadowrocket sections, policies, DNS, and rule-order tests.
- `tests/test_clash_script.cjs`: Node tests for profile preservation and strict overrides.
- `.github/workflows/validate.yml`: push/PR validation and scheduled upstream-diff PR.
- `README.md`: installation, airport changes, DNS/WebRTC interpretation, testing, rollback, and attribution.
- `LICENSE`: GPL-3.0 text.

---

### Task 1: Project Foundation and Canonical Rule Model

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `scripts/__init__.py`
- Create: `scripts/lib/__init__.py`
- Create: `scripts/lib/model.py`
- Create: `tests/test_model.py`

**Interfaces:**
- Produces: `Rule(type: str, value: str, targets: frozenset[str], note: str | None)`.
- Produces: `load_rule_file(path: Path) -> list[Rule]`.
- Produces: `load_rule_tree(root: Path) -> list[Rule]`.
- Produces: `rules_for_target(rules: Iterable[Rule], target: str) -> list[Rule]`.

- [ ] **Step 1: Add the Python project metadata and ignore rules**

Create `pyproject.toml` with:

```toml
[build-system]
requires = ["setuptools>=69"]
build-backend = "setuptools.build_meta"

[project]
name = "proxy-rules"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["PyYAML>=6.0,<7"]

[project.optional-dependencies]
dev = ["pytest>=8,<9"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-ra"

[tool.setuptools.packages.find]
include = ["scripts*"]
```

Create `.gitignore` with:

```gitignore
__pycache__/
*.py[cod]
.pytest_cache/
.venv/
.cache/
coverage.xml
.coverage
client-exports/
```

- [ ] **Step 2: Write failing canonical-model tests**

Create `tests/test_model.py` containing these cases:

```python
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
```

- [ ] **Step 3: Run the model tests and verify the expected failure**

Run: `python3 -m pip install -e '.[dev]' && pytest tests/test_model.py -q`

Expected: collection fails with `ModuleNotFoundError: No module named 'scripts.lib.model'`.

- [ ] **Step 4: Implement the canonical model**

Create `scripts/lib/model.py` with these exact validation rules:

```python
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network
from pathlib import Path
from typing import Iterable

import yaml

SUPPORTED_TYPES = {"domain", "domain-suffix", "domain-keyword", "ip-cidr", "ip-asn", "process-name"}
SUPPORTED_TARGETS = frozenset({"shadowrocket", "mihomo"})


class RuleError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class Rule:
    type: str
    value: str
    targets: frozenset[str] = SUPPORTED_TARGETS
    note: str | None = None


def _normalize(rule_type: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuleError("rule value must be a non-empty string")
    value = value.strip()
    if rule_type in {"domain", "domain-suffix"}:
        return value.rstrip(".").lower()
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
        result.append(Rule(rule_type, _normalize(rule_type, item.get("value")), targets, item.get("note")))
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
```

Create empty package markers `scripts/__init__.py` and `scripts/lib/__init__.py`.

- [ ] **Step 5: Run the tests and commit**

Run: `pytest tests/test_model.py -q`

Expected: `4 passed`.

Commit:

```bash
git add pyproject.toml .gitignore scripts tests/test_model.py
git commit -m "feat: add canonical rule model"
```

---

### Task 2: Reproducible Upstream Snapshots

**Files:**
- Create: `source/upstreams.yaml`
- Create: `source/upstream/`
- Create: `scripts/lib/upstream.py`
- Create: `scripts/sync_upstreams.py`
- Create: `tests/test_upstream.py`
- Generate: `source/upstream.lock.json`

**Interfaces:**
- Consumes: upstream YAML `payload` arrays and OpenAI `prefixes` JSON.
- Produces: `normalize_domain_payload(payload: list[str]) -> list[Rule]`.
- Produces: `normalize_ip_payload(payload: list[str]) -> list[Rule]`.
- Produces: `sync_manifest(manifest: Path, repo_root: Path, update: bool, opener: Callable) -> dict`.

- [ ] **Step 1: Add the exact upstream manifest**

Create `source/upstreams.yaml` with these sources:

```yaml
version: 1
sets:
  reject-domain:
    parser: domain-yaml
    output: source/upstream/reject-domain.yaml
    urls: [https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/category-ads-all.yaml]
  cn-domain:
    parser: domain-yaml
    output: source/upstream/cn-domain.yaml
    urls: [https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/cn.yaml]
  cn-ip:
    parser: ip-yaml
    output: source/upstream/cn-ip.yaml
    urls: [https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geoip/cn.yaml]
  media-domain:
    parser: domain-yaml
    output: source/upstream/media-domain.yaml
    urls:
      - https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/youtube.yaml
      - https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/netflix.yaml
      - https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/disney.yaml
      - https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/hbo.yaml
      - https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/spotify.yaml
      - https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/tiktok.yaml
  messaging-domain:
    parser: domain-yaml
    output: source/upstream/messaging-domain.yaml
    urls:
      - https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/telegram.yaml
      - https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/discord.yaml
  apple-microsoft-domain:
    parser: domain-yaml
    output: source/upstream/apple-microsoft-domain.yaml
    urls:
      - https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/apple.yaml
      - https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/microsoft.yaml
  openai-voice:
    parser: openai-voice-json
    output: source/ai/openai-voice.yaml
    urls: [https://openai.com/chatgpt-voice.json]
```

- [ ] **Step 2: Write failing parser, lock, and atomic-update tests**

Create `tests/test_upstream.py` with in-memory response fixtures and these assertions:

```python
def test_domain_payload_normalizes_exact_and_suffix():
    rules = normalize_domain_payload(["example.com", "+.Example.NET", "*.example.org"])
    assert [(r.type, r.value) for r in rules] == [
        ("domain", "example.com"),
        ("domain-suffix", "example.net"),
        ("domain-suffix", "example.org"),
    ]


def test_openai_voice_rejects_empty_prefixes():
    with pytest.raises(UpstreamError, match="prefixes is empty"):
        parse_openai_voice(b'{"prefixes": []}')


def test_failed_update_preserves_existing_snapshot(tmp_path):
    snapshot = tmp_path / "source/upstream/cn-domain.yaml"
    snapshot.parent.mkdir(parents=True)
    snapshot.write_text("version: 1\nrules: []\n")
    with pytest.raises(UpstreamError):
        sync_manifest(tmp_path / "source/upstreams.yaml", tmp_path, True, failing_opener)
    assert snapshot.read_text() == "version: 1\nrules: []\n"
```

Also assert that a successful update records `url`, `retrieved_at`, `raw_sha256`, `normalized_sha256`, and writes sets sorted by `(type, value)`.

Add a regression test that runs the same successful update twice with different clocks and identical response bytes. Assert the second run preserves the first lock entry, including `retrieved_at`, and reports no change. For multi-URL sets, store a `sources` array containing one `url` and `raw_sha256` per response plus one set-level `normalized_sha256`.

- [ ] **Step 3: Run the tests and verify failure**

Run: `pytest tests/test_upstream.py -q`

Expected: import failure for `scripts.lib.upstream`.

- [ ] **Step 4: Implement deterministic normalization and atomic updates**

Implement `scripts/lib/upstream.py` with these core functions:

```python
class UpstreamError(RuntimeError):
    pass


def normalize_domain_payload(payload: list[str]) -> list[Rule]:
    result: set[Rule] = set()
    for raw in payload:
        if not isinstance(raw, str) or not raw.strip():
            raise UpstreamError("domain payload contains a non-string or empty entry")
        value = raw.strip().lower().rstrip(".")
        if value.startswith(("+.", "*.")):
            result.add(Rule("domain-suffix", value[2:]))
        elif any(token in value for token in ("*", "?", "regexp:")):
            raise UpstreamError(f"unsupported upstream domain expression: {raw}")
        else:
            result.add(Rule("domain", value))
    return sorted(result, key=lambda rule: (rule.type, rule.value))


def normalize_ip_payload(payload: list[str]) -> list[Rule]:
    from ipaddress import ip_network
    result = {Rule("ip-cidr", str(ip_network(value, strict=False))) for value in payload}
    return sorted(result, key=lambda rule: rule.value)


def parse_openai_voice(raw: bytes) -> list[Rule]:
    data = json.loads(raw)
    prefixes = data.get("prefixes")
    if not isinstance(prefixes, list) or not prefixes:
        raise UpstreamError("OpenAI voice prefixes is empty")
    values = []
    for item in prefixes:
        value = item.get("ipv4Prefix") or item.get("ipv6Prefix")
        if not value:
            raise UpstreamError("OpenAI voice prefix entry has no IP prefix")
        values.append(value)
    return normalize_ip_payload(values)


def render_snapshot(rules: list[Rule]) -> bytes:
    data = {"version": 1, "rules": [{"type": r.type, "value": r.value} for r in rules]}
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=False).encode()
```

Implement `sync_manifest()` so it downloads every URL before writing anything, parses YAML only from a top-level non-empty `payload` list, combines and deduplicates rules per set, prepares every snapshot and the complete lock in memory, and only then atomically replaces all target files with `NamedTemporaryFile` plus `os.replace`. Use a 30-second timeout and User-Agent `jwenwen233/proxy-rules`. If every raw hash and the normalized bytes are unchanged, preserve the existing lock entry byte-for-byte rather than refreshing `retrieved_at`. In check mode compare raw hashes and prepared snapshot bytes while ignoring the current clock, and exit non-zero only for a real content/hash change without writing.

Create `scripts/sync_upstreams.py` with mutually exclusive required flags `--update` and `--check` and call `sync_manifest(Path("source/upstreams.yaml"), Path.cwd(), args.update, default_opener)`.

- [ ] **Step 5: Run unit tests, perform the first real update, and verify offline data**

Run:

```bash
pytest tests/test_upstream.py -q
python3 scripts/sync_upstreams.py --update
python3 - <<'PY'
from pathlib import Path
import json
lock = json.loads(Path('source/upstream.lock.json').read_text())
assert len(lock['sets']) == 7
for entry in lock['sets'].values():
    assert entry['normalized_sha256']
print('upstream snapshots:', len(lock['sets']))
PY
```

Expected: all upstream tests pass and verification prints `upstream snapshots: 7`.

- [ ] **Step 6: Commit the reproducible snapshots**

```bash
git add source scripts/lib/upstream.py scripts/sync_upstreams.py tests/test_upstream.py
git commit -m "feat: add reproducible upstream snapshots"
```

---

### Task 3: Curated Personal and AI Sources plus Client Generators

**Files:**
- Create: `source/personal/direct.yaml`
- Create: `source/personal/proxy.yaml`
- Create: `source/personal/reject.yaml`
- Create: `source/ai/anthropic.yaml`
- Create: `source/ai/openai.yaml`
- Create: `scripts/lib/generate.py`
- Create: `scripts/build_rules.py`
- Create: `tests/test_generation.py`
- Generate: `dist/shadowrocket/*.list`
- Generate: `dist/mihomo/*.yaml`

**Interfaces:**
- Consumes: `Rule` lists from curated files and tracked upstream snapshots.
- Produces: `render_shadowrocket(rules: Iterable[Rule]) -> str`.
- Produces: `choose_mihomo_behavior(rules: Sequence[Rule]) -> str`.
- Produces: `render_mihomo(rules: Sequence[Rule], behavior: str) -> str`.
- Produces: `build_all(repo_root: Path) -> dict[Path, str]`.

- [ ] **Step 1: Add the curated personal and AI records**

Create `source/personal/direct.yaml`:

```yaml
version: 1
rules:
  - {type: domain-suffix, value: todesk.com}
  - {type: domain-suffix, value: todesk.cn}
  - {type: domain-suffix, value: scnet.cn}
  - {type: process-name, value: ToDesk, targets: [mihomo]}
```

Use this valid empty structure for both `source/personal/proxy.yaml` and `source/personal/reject.yaml`:

```yaml
version: 1
rules: []
```

Create `source/ai/anthropic.yaml`:

```yaml
version: 1
rules:
  - {type: domain-suffix, value: anthropic.com}
  - {type: domain-suffix, value: claude.ai}
  - {type: domain-suffix, value: claude.com}
  - {type: domain-suffix, value: clau.de}
  - {type: domain-suffix, value: claudemcpclient.com}
  - {type: domain-suffix, value: claudemcpcontent.com}
  - {type: domain-suffix, value: claudeusercontent.com}
  - {type: ip-cidr, value: 160.79.104.0/21}
```

Create `source/ai/openai.yaml`:

```yaml
version: 1
rules:
  - {type: domain-suffix, value: openai.com}
  - {type: domain-suffix, value: chatgpt.com}
  - {type: domain-suffix, value: oaistatic.com}
  - {type: domain-suffix, value: oaiusercontent.com}
  - {type: domain-suffix, value: oaistatsig.com}
  - {type: domain-suffix, value: openaimerge.com}
  - {type: domain, value: cdn.workos.com}
  - {type: domain, value: forwarder.workos.com}
  - {type: domain, value: humb.apple.com}
  - {type: domain, value: images.workoscdn.com}
  - {type: domain, value: js.intercomcdn.com}
  - {type: domain, value: js.stripe.com}
  - {type: domain, value: o207216.ingest.sentry.io}
  - {type: domain, value: o33249.ingest.sentry.io}
  - {type: domain, value: rum.browser-intake-datadoghq.com}
  - {type: domain, value: setup.workos.com}
  - {type: domain, value: workos.imgix.net}
  - {type: domain, value: challenges.cloudflare.com}
```

- [ ] **Step 2: Write failing rendering and determinism tests**

Create `tests/test_generation.py` with these exact assertions:

```python
def test_shadowrocket_rendering():
    rules = [
        Rule("domain", "api.example.com"),
        Rule("domain-suffix", "example.org"),
        Rule("ip-cidr", "192.0.2.0/24"),
        Rule("ip-asn", "399358"),
    ]
    assert render_shadowrocket(rules) == (
        "DOMAIN,api.example.com\n"
        "DOMAIN-SUFFIX,example.org\n"
        "IP-ASN,399358,no-resolve\n"
        "IP-CIDR,192.0.2.0/24,no-resolve\n"
    )


def test_mihomo_behavior_selection():
    assert choose_mihomo_behavior([Rule("domain", "a.example")]) == "domain"
    assert choose_mihomo_behavior([Rule("ip-cidr", "192.0.2.0/24")]) == "ipcidr"
    assert choose_mihomo_behavior([
        Rule("domain-suffix", "example.com"), Rule("ip-cidr", "192.0.2.0/24")
    ]) == "classical"


def test_process_name_is_target_specific():
    rule = Rule("process-name", "ToDesk", frozenset({"mihomo"}))
    assert render_shadowrocket([rule]) == ""
    assert "PROCESS-NAME,ToDesk" in render_mihomo([rule], "classical")


def test_build_is_deterministic():
    repo_root = Path(__file__).parents[1]
    assert build_all(repo_root) == build_all(repo_root)
```

- [ ] **Step 3: Run tests and verify failure**

Run: `pytest tests/test_generation.py -q`

Expected: import failure for `scripts.lib.generate`.

- [ ] **Step 4: Implement rendering and the offline build map**

Implement `scripts/lib/generate.py` using these exact mappings:

```python
SHADOWROCKET_TYPES = {
    "domain": "DOMAIN",
    "domain-suffix": "DOMAIN-SUFFIX",
    "domain-keyword": "DOMAIN-KEYWORD",
    "ip-cidr": "IP-CIDR",
    "ip-asn": "IP-ASN",
}
MIHOMO_CLASSICAL_TYPES = {**SHADOWROCKET_TYPES, "process-name": "PROCESS-NAME"}


def render_shadowrocket(rules):
    lines = []
    for rule in sorted(rules_for_target(rules, "shadowrocket"), key=lambda r: (r.type, r.value)):
        suffix = ",no-resolve" if rule.type in {"ip-cidr", "ip-asn"} else ""
        lines.append(f"{SHADOWROCKET_TYPES[rule.type]},{rule.value}{suffix}")
    return "\n".join(lines) + ("\n" if lines else "")


def choose_mihomo_behavior(rules):
    types = {rule.type for rule in rules_for_target(rules, "mihomo")}
    if types <= {"domain", "domain-suffix"}:
        return "domain"
    if types == {"ip-cidr"}:
        return "ipcidr"
    return "classical"
```

For Mihomo `domain` behavior, render exact domains unchanged and suffixes as `+.domain`; for `ipcidr`, render bare CIDRs; for `classical`, render `TYPE,value` and append `,no-resolve` to IP rules. Wrap output as a stable YAML mapping with one `payload` array and no anchors.

Implement `build_all()` with this fixed composition:

| Output | Source inputs |
|---|---|
| `direct` | `source/personal/direct.yaml` |
| `reject-domain` | `source/personal/reject.yaml` + `source/upstream/reject-domain.yaml` |
| `ai` | `source/ai/anthropic.yaml` + `source/ai/openai.yaml` |
| `openai-voice-ip` | `source/ai/openai-voice.yaml` |
| `media` | `source/upstream/media-domain.yaml` |
| `messaging` | `source/upstream/messaging-domain.yaml` |
| `apple-microsoft` | `source/upstream/apple-microsoft-domain.yaml` |
| `cn-domain` | `source/upstream/cn-domain.yaml` |
| `cn-ip` | `source/upstream/cn-ip.yaml` |

Generate the matching Shadowrocket names, combining both CN sources into `dist/shadowrocket/cn.list` and AI plus voice into `dist/shadowrocket/ai.list`. Write all outputs atomically only after every file renders.

Create `scripts/build_rules.py` with a `--check` flag. Normal mode atomically writes `build_all(Path.cwd())`; check mode compares render content with tracked files and exits 1 on a missing, extra, or changed generated file.

- [ ] **Step 5: Run tests, build twice, and commit**

```bash
pytest tests/test_generation.py -q
python3 scripts/build_rules.py
python3 scripts/build_rules.py --check
git diff --exit-code -- dist
```

Expected: tests pass, check mode exits 0, and the second build leaves no diff.

```bash
git add source/personal source/ai scripts/lib/generate.py scripts/build_rules.py tests/test_generation.py dist
git commit -m "feat: generate client rule sets"
```

---

### Task 4: Repository Validation, Precedence, and Secret Scanning

**Files:**
- Create: `scripts/lib/validation.py`
- Create: `scripts/validate.py`
- Create: `tests/test_validation.py`

**Interfaces:**
- Produces: `validate_rule_conflicts(named_sets: dict[str, list[Rule]]) -> list[str]`.
- Produces: `validate_generated_files(root: Path) -> list[str]`.
- Produces: `scan_secrets(root: Path) -> list[str]`.
- Produces: `validate_repository(root: Path) -> None`, raising `ValidationError` with all findings.

- [ ] **Step 1: Write failing validation tests**

Cover these concrete failures:

```python
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
def test_secret_scanner_rejects_credentials(tmp_path, secret):
    (tmp_path / "bad.txt").write_text(secret)
    assert scan_secrets(tmp_path)


def test_readme_plain_protocol_names_are_allowed(tmp_path):
    (tmp_path / "README.md").write_text("Supported protocol names: VLESS, VMess, Trojan.")
    assert scan_secrets(tmp_path) == []
```

Add precedence tests for `claude.ai -> PRX-AI`, `chatgpt.com -> PRX-AI`, `scnet.cn -> DIRECT`, `192.168.1.1 -> DIRECT`, an ad fixture -> `REJECT`, and an unknown `example.net -> PRX-Proxy`.

- [ ] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_validation.py -q`

Expected: import failure for `scripts.lib.validation`.

- [ ] **Step 3: Implement aggregate validation**

Use case-insensitive credential patterns for proxy URI schemes, UUIDs adjacent to proxy URI syntax, private/Reality key fields, subscription user info, and credential-shaped subscription query values. Build detector literals from fragments such as `"vless:" + r"//"` so the scanner source does not match itself. Exclude `.git/`, `work/`, `.cache/`, binary files, and `docs/superpowers/`; the latter contains deliberate dummy detection examples and is separately covered by the repository-wide `git grep` check. Scan `README.md` and all user-facing documentation normally. Allow harmless prose that names protocols but contains no URI or credentials.

Validate policy references against:

```python
POLICIES = {
    "DIRECT", "REJECT", "PRX-Manual", "PRX-Auto", "PRX-AI",
    "PRX-Media", "PRX-Messaging", "PRX-Apple-Microsoft", "PRX-Proxy",
}
```

Reject `domain-keyword` without a non-empty note, non-normalized IPs, duplicate/conflicting rules, empty required outputs, unknown policies, stale generated files, and unresolved repository URL placeholders. Create `scripts/validate.py` to print all findings and exit 1, or print `validation: OK` and exit 0.

- [ ] **Step 4: Run focused and repository validation, then commit**

```bash
pytest tests/test_validation.py -q
python3 scripts/validate.py
git add scripts/lib/validation.py scripts/validate.py tests/test_validation.py
git commit -m "feat: validate rules and reject secrets"
```

Expected: tests pass and the CLI prints `validation: OK`.

---

### Task 5: Shadowrocket Configuration

**Files:**
- Create: `configs/shadowrocket.conf`
- Create: `tests/test_shadowrocket.py`

**Interfaces:**
- Consumes: public `dist/shadowrocket/*.list` raw URLs.
- Produces: a node-free Shadowrocket configuration with `PRX-*` groups.

- [ ] **Step 1: Write failing Shadowrocket structure and DNS tests**

Create tests that parse `[General]`, `[Proxy Group]`, and `[Rule]` and assert:

```python
assert general["dns-server"] == "https://1.1.1.1/dns-query#proxy"
assert general["fallback-dns-server"] == "https://1.0.0.1/dns-query#proxy"
assert general["proxy-dns-server"] == "https://1.1.1.1/dns-query"
assert general["dns-direct-system"] == "false"
assert general["ipv6"] == "false"
assert general["prefer-ipv6"] == "false"
assert general["udp-policy-not-supported-behaviour"] == "REJECT"
assert "system" not in general["dns-server"]
assert "system" not in general["fallback-dns-server"]
assert "dns-fallback-system" not in general
```

Assert all seven `PRX-*` groups exist, `PRX-AI` lacks `DIRECT`, embedded Claude/OpenAI rules appear before remote providers, CN rules appear after AI/media/messaging, and `FINAL,PRX-Proxy` is last.

- [ ] **Step 2: Run tests and verify failure**

Run: `pytest tests/test_shadowrocket.py -q`

Expected: failure because `configs/shadowrocket.conf` does not exist.

- [ ] **Step 3: Create the node-free configuration**

Use these exact General values:

```ini
[General]
dns-server = https://1.1.1.1/dns-query#proxy
fallback-dns-server = https://1.0.0.1/dns-query#proxy
proxy-dns-server = https://1.1.1.1/dns-query
dns-direct-system = false
dns-direct-fallback-proxy = false
use-local-host-item-for-proxy = false
ipv6 = false
prefer-ipv6 = false
hijack-dns = 8.8.8.8:53,8.8.4.4:53
udp-policy-not-supported-behaviour = REJECT
skip-proxy = 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,localhost,*.local,captive.apple.com
```

Define `PRX-Manual` and `PRX-Auto` with `policy-regex-filter=^((?!(剩余|流量|套餐|到期|官网|更新|订阅|客服|Expire|Traffic|Website)).)*$`. Define the remaining select groups with these exact members and order:

```text
PRX-AI = PRX-Manual,PRX-Auto
PRX-Media = PRX-Manual,PRX-Auto
PRX-Messaging = PRX-Manual,PRX-Auto
PRX-Apple-Microsoft = DIRECT,PRX-Manual,PRX-Auto
PRX-Proxy = PRX-Manual,PRX-Auto
```

Embed private ranges, ToDesk/scnet, `anthropic.com`, `claude.ai`, `claude.com`, `openai.com`, `chatgpt.com`, `oaistatic.com`, and `oaiusercontent.com` before remote rule sets. Reference only concrete URLs beneath:

```text
https://raw.githubusercontent.com/jwenwen233/proxy-rules/main/dist/shadowrocket/
```

End with `GEOIP,CN,DIRECT` followed by `FINAL,PRX-Proxy`. Do not add `[Proxy]`, MITM, certificates, node URIs, or subscription URLs.

- [ ] **Step 4: Run tests and commit**

```bash
pytest tests/test_shadowrocket.py -q
python3 scripts/validate.py
git add configs/shadowrocket.conf tests/test_shadowrocket.py
git commit -m "feat: add strict Shadowrocket configuration"
```

Expected: all tests pass and validation prints `validation: OK`.

---

### Task 6: Clash Verge Global Enhancement Script

**Files:**
- Create: `configs/clash-verge-script.js`
- Create: `tests/fixtures/airport.json`
- Create: `tests/test_clash_script.cjs`

**Interfaces:**
- Produces: global `main(config: object) -> object` for Clash Verge.
- Exports under Node only: `{ main, makeGroups, makeRuleProviders, makeRules }`.

- [ ] **Step 1: Add an airport fixture that exercises preservation**

Create `tests/fixtures/airport.json`:

```json
{
  "mixed-port": 7890,
  "proxies": [{"name": "US-01", "type": "socks5", "server": "127.0.0.1", "port": 1080}],
  "proxy-providers": {"Airport": {"type": "file", "path": "./provider.yaml"}},
  "proxy-groups": [{"name": "Airport-Chain", "type": "select", "proxies": ["US-01"]}],
  "rule-providers": {"Airport-Rules": {"type": "file", "behavior": "classical", "path": "./airport-rules.yaml"}},
  "rules": ["MATCH,DIRECT"],
  "dns": {"enable": true, "nameserver": ["system"], "fallback": ["8.8.8.8"]},
  "tun": {"enable": false, "stack": "gvisor"}
}
```

- [ ] **Step 2: Write failing Node tests**

Use `node:test` and `node:assert/strict`; load `tests/fixtures/airport.json` so no Node YAML package is required. Deep-clone the object before each call to avoid cross-test mutation. Assert:

```javascript
assert.equal(output['mixed-port'], 7890);
assert.equal(output.tun.enable, false);
assert.equal(output.tun.stack, 'gvisor');
assert.deepEqual(output.tun['dns-hijack'], ['any:53']);
assert.equal(output.ipv6, false);
assert.deepEqual(output.dns.nameserver, ['https://1.1.1.1/dns-query#PRX-Proxy']);
assert.deepEqual(output.dns['default-nameserver'], ['https://1.1.1.1/dns-query#DIRECT']);
assert.deepEqual(output.dns['proxy-server-nameserver'], ['https://1.1.1.1/dns-query#DIRECT']);
assert.equal('fallback' in output.dns, false);
assert.equal('nameserver-policy' in output.dns, false);
assert.ok(output['proxy-groups'].some(group => group.name === 'Airport-Chain'));
assert.ok(output['proxy-groups'].some(group => group.name === 'PRX-Proxy'));
assert.equal(output.rules.at(-1), 'MATCH,PRX-Proxy');
assert.equal(output.rules.includes('MATCH,DIRECT'), false);
```

Also assert `PRX-Manual` and `PRX-Auto` have `include-all: true`, every generated HTTP rule provider has `proxy: PRX-Proxy`, and a pre-existing node/group/provider whose name starts with `PRX-` throws a reserved-name error.

- [ ] **Step 3: Run Node tests and verify failure**

Run: `node --test tests/test_clash_script.cjs`

Expected: failure because `configs/clash-verge-script.js` does not exist.

- [ ] **Step 4: Implement the enhancement script**

Start with strict helpers:

```javascript
const PREFIX = 'PRX-';
const RAW = 'https://raw.githubusercontent.com/jwenwen233/proxy-rules/main/dist/mihomo';
const INFO_FILTER = '(?i)剩余|流量|套餐|到期|官网|更新|订阅|客服|expire|traffic|website';

function assertNoReservedNames(config) {
  const names = [
    ...(config.proxies || []).map(item => item.name),
    ...(config['proxy-groups'] || []).map(item => item.name),
    ...Object.keys(config['rule-providers'] || {}),
  ];
  const collision = names.find(name => typeof name === 'string' && name.startsWith(PREFIX));
  if (collision) throw new Error(`reserved ${PREFIX} name in airport profile: ${collision}`);
}
```

Create `PRX-Manual` as `select` and `PRX-Auto` as `url-test`, both with `include-all: true` and `exclude-filter: INFO_FILTER`. Use `https://www.gstatic.com/generate_204`, interval `600`, timeout `5000`, and tolerance `100` for Auto. Build these exact select groups:

```javascript
const SELECT_GROUPS = {
  'PRX-AI': ['PRX-Manual', 'PRX-Auto'],
  'PRX-Media': ['PRX-Manual', 'PRX-Auto'],
  'PRX-Messaging': ['PRX-Manual', 'PRX-Auto'],
  'PRX-Apple-Microsoft': ['DIRECT', 'PRX-Manual', 'PRX-Auto'],
  'PRX-Proxy': ['PRX-Manual', 'PRX-Auto'],
};
```

Generate namespaced providers with `type: http`, `format: yaml`, `interval: 86400`, `proxy: PRX-Proxy`, unique `./ruleset/prx-*.yaml` paths, concrete raw URLs, and these behaviors:

```javascript
const PROVIDERS = {
  'PRX-RULE-direct': ['classical', 'direct.yaml'],
  'PRX-RULE-reject-domain': ['domain', 'reject-domain.yaml'],
  'PRX-RULE-ai': ['classical', 'ai.yaml'],
  'PRX-RULE-openai-voice-ip': ['ipcidr', 'openai-voice-ip.yaml'],
  'PRX-RULE-media': ['domain', 'media.yaml'],
  'PRX-RULE-messaging': ['domain', 'messaging.yaml'],
  'PRX-RULE-apple-microsoft': ['domain', 'apple-microsoft.yaml'],
  'PRX-RULE-cn-domain': ['domain', 'cn-domain.yaml'],
  'PRX-RULE-cn-ip': ['ipcidr', 'cn-ip.yaml'],
};
```

In `main`, preserve existing non-reserved groups/providers, replace `rules` completely, set `ipv6 = false`, and remove old DNS keys that can create another path:

```javascript
const {
  fallback, 'fallback-filter': fallbackFilter,
  'nameserver-policy': nameserverPolicy,
  'direct-nameserver': directNameserver,
  ...dnsRuntime
} = config.dns || {};
config.dns = {
  ...dnsRuntime,
  enable: true,
  ipv6: false,
  'enhanced-mode': 'fake-ip',
  'use-hosts': false,
  'use-system-hosts': false,
  'respect-rules': true,
  nameserver: ['https://1.1.1.1/dns-query#PRX-Proxy'],
  'default-nameserver': ['https://1.1.1.1/dns-query#DIRECT'],
  'proxy-server-nameserver': ['https://1.1.1.1/dns-query#DIRECT'],
  'fake-ip-filter': ['*.lan', '*.local', 'localhost.ptlogin2.qq.com', 'captive.apple.com'],
};
config.tun = {...(config.tun || {}), 'dns-hijack': ['any:53']};
```

`makeRules()` must return embedded LAN/private, ToDesk/scnet, and critical AI rules first, followed by providers in this order: direct, reject-domain, AI, OpenAI voice IP, messaging, media, Apple/Microsoft, CN domain, CN IP, then `GEOIP,CN,DIRECT,no-resolve` and `MATCH,PRX-Proxy`. Under Node, export functions only when `module` exists:

```javascript
if (typeof module !== 'undefined') {
  module.exports = {main, makeGroups, makeRuleProviders, makeRules};
}
```

- [ ] **Step 5: Run Node, Python, and Mihomo configuration tests**

```bash
node --test tests/test_clash_script.cjs
pytest -q
python3 scripts/validate.py
```

Compose the JSON fixture through `main()` and run the pinned Mihomo binary. JSON is valid YAML, so no conversion dependency is needed:

```bash
mkdir -p .cache
curl -fL https://github.com/MetaCubeX/mihomo/releases/download/v1.19.28/mihomo-darwin-arm64-v1.19.28.gz -o .cache/mihomo.gz
echo '40cdae2fab4b18df15f40eaa9dc3af70ab3d8be7f77164ae1e5f1af3a2a4fb44  .cache/mihomo.gz' | shasum -a 256 -c -
gzip -dc .cache/mihomo.gz > .cache/mihomo
chmod +x .cache/mihomo
node -e "const {main}=require('./configs/clash-verge-script.js'); const c=require('./tests/fixtures/airport.json'); process.stdout.write(JSON.stringify(main(c)))" > .cache/test-config.yaml
.cache/mihomo -t -f .cache/test-config.yaml
```

Expected: Node and Python tests pass, validation prints `validation: OK`, and Mihomo prints configuration-valid output and exits 0.

- [ ] **Step 6: Commit**

```bash
git add configs/clash-verge-script.js tests/fixtures/airport.json tests/test_clash_script.cjs
git commit -m "feat: add Clash Verge enhancement script"
```

---

### Task 7: CI, Scheduled Review PR, Documentation, and License

**Files:**
- Create: `.github/workflows/validate.yml`
- Create: `README.md`
- Create: `LICENSE`
- Modify: `scripts/validate.py`
- Modify: `tests/test_validation.py`

**Interfaces:**
- Consumes: all local test/build/validation commands.
- Produces: repeatable CI and user installation/rollback instructions.

- [ ] **Step 1: Add a failing documentation contract test**

Add this test to `tests/test_validation.py`:

```python
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
```

Run: `pytest tests/test_validation.py::test_readme_has_operating_sections -q`

Expected: failure because `README.md` is absent.

- [ ] **Step 2: Write exact operating documentation and license**

Document this installation order:

1. Import and test the airport subscription first.
2. Import `configs/shadowrocket.conf` in Shadowrocket or paste `configs/clash-verge-script.js` into Clash Verge Global Script.
3. Select a usable node in `PRX-Manual` or allow `PRX-Auto` to test nodes.
4. Enable rule/config mode; enable TUN manually in Clash Verge only when full-device capture is desired.
5. Change airports by replacing the local subscription only; do not edit public configuration files.

Explain that Cloudflare resolver IPs can appear in multiple anycast cities without constituting an ISP DNS leak; a resolver belonging to the mobile/broadband ISP is the failure signal. Explain that different proxy-owned HTTP and STUN IPs indicate provider-side TCP/UDP split egress, while the local ISP public IP in STUN is a real leak. State that the configurations do not disable WebRTC or UDP.

Document rollback: disable Global Script or the selected Shadowrocket config, restore the previous profile, and leave the subscription untouched. Include upstream attribution and direct links to Anthropic, OpenAI, MetaCubeX, Mihomo, Clash Verge Rev, and the Shadowrocket community manual.

Add the unmodified GPL-3.0 license text to `LICENSE`.

- [ ] **Step 3: Add push/PR validation workflow**

Create `.github/workflows/validate.yml` with `contents: read` by default. For pushes and pull requests use:

```yaml
- uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
- uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
  with: {python-version: '3.11'}
- uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4
  with: {node-version: '20'}
- run: python -m pip install -e '.[dev]'
- run: pytest -q
- run: node --test tests/test_clash_script.cjs
- run: python scripts/build_rules.py --check
- run: python scripts/validate.py
```

Before the tests, download Mihomo v1.19.28 from `https://github.com/MetaCubeX/mihomo/releases/download/v1.19.28/mihomo-linux-amd64-compatible-v1.19.28.gz`, verify SHA-256 `70d01cfb8cb7bf7a92fd1af16cb4b9553d90bb4eecde3b5c4849103e27c80ddb`, extract it to `.cache/mihomo`, and run the fixture composition and `mihomo -t` commands from Task 6.

Add a scheduled job at `17 3 * * *` that checks out a branch, runs `python scripts/sync_upstreams.py --update`, rebuilds and validates, and uses `peter-evans/create-pull-request@22a9089034f40e5a961c8808d113e2c98fb63676` (v7). Grant `contents: write` and `pull-requests: write` only to the scheduled job. Use branch `automation/update-rules`, title `chore: update upstream rules`, and never push directly to `main`.

- [ ] **Step 4: Run the full local release gate**

Run fresh:

```bash
python3 -m pip install -e '.[dev]'
pytest -q
node --test tests/test_clash_script.cjs
python3 scripts/build_rules.py --check
python3 scripts/validate.py
git diff --check
```

Expected: every command exits 0, pytest and Node report zero failures, build check produces no diff, validator prints `validation: OK`, and `git diff --check` prints nothing.

- [ ] **Step 5: Commit documentation and automation**

```bash
git add .github/workflows/validate.yml README.md LICENSE tests/test_validation.py scripts/validate.py
git commit -m "docs: add installation and automated validation"
```

---

### Task 8: Two-Client Acceptance, Security Review, and Publication Readiness

**Files:**
- Modify only if a verified failure requires it: `configs/shadowrocket.conf`, `configs/clash-verge-script.js`, `README.md`, and the relevant tests.
- Do not create tracked files containing node or subscription exports.

**Interfaces:**
- Consumes: one test subscription in each client, then a second different subscription.
- Produces: verified local release candidate; publication remains a separate user-approved action.

- [ ] **Step 1: Verify repository cleanliness before importing private data**

Run:

```bash
git status --short
python3 scripts/validate.py
git grep -nEi 'vless://|vmess://|trojan://|ss://|privateKey|subscription-userinfo' -- ':!docs/superpowers/**'
```

Expected: only the pre-existing untracked `work/` may appear; validation passes; credential grep has no matches.

- [ ] **Step 2: Perform Shadowrocket acceptance without exporting nodes**

On the device, import a test airport separately, apply `shadowrocket.conf`, and verify:

- `PRX-Manual` and `PRX-Auto` contain actual imported nodes, not informational entries.
- `claude.ai` and `chatgpt.com` match `PRX-AI` in rule testing/logs.
- `scnet.cn` matches `DIRECT`; a representative advertisement matches `REJECT`; an unknown overseas domain reaches `PRX-Proxy`.
- DNS leak testing shows Cloudflare resolvers and no mobile/broadband ISP resolver.
- WebRTC shows either the selected proxy IP or a provider-owned UDP egress, never the local ISP public IP.
- A UDP-capable node supports voice/QUIC; a TCP-only node rejects unsupported UDP instead of going direct.

Record only pass/fail notes in the task conversation, not IPs, node names, screenshots containing subscriptions, or exported profiles in the repository.

- [ ] **Step 3: Perform Clash Verge acceptance with two airport profiles**

Apply the Global Script to the current profile and verify TUN remains at its prior enabled/disabled value. Check `PRX-*` groups, strict DNS through the Mihomo API, Claude/ChatGPT routing, China direct routing, advertisement rejection, final proxy routing, and UDP behavior. Switch to a second airport profile and repeat without editing the script.

- [ ] **Step 4: Convert every discovered failure into a regression test before fixing**

For a Shadowrocket failure, add the smallest failing case to `tests/test_shadowrocket.py`; for a Clash failure, add it to `tests/test_clash_script.cjs`; for rule data, add it to `tests/test_validation.py`. Run the focused test to see it fail, apply the minimal fix, rerun the focused test, then rerun the full release gate from Task 7.

- [ ] **Step 5: Final local commit and publication handoff**

If acceptance required fixes, commit only the relevant files:

```bash
git add configs tests README.md source scripts dist
git commit -m "fix: address client acceptance findings"
```

Then run:

```bash
git status --short
git log --oneline --decorate -10
python3 scripts/validate.py
```

Expected: only `work/` remains untracked, commit history is intentional, and validation prints `validation: OK`. Stop here and request explicit user approval before creating the public GitHub repository or pushing any branch.
