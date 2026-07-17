import json
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from scripts.lib.upstream import (
    UpstreamError,
    normalize_domain_payload,
    parse_openai_voice,
    sync_manifest,
)


class Response:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def read(self) -> bytes:
        return self.body

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *_: object) -> None:
        return None


def write_manifest(tmp_path: Path, sets: dict[str, dict[str, object]]) -> Path:
    manifest = tmp_path / "source/upstreams.yaml"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(yaml.safe_dump({"version": 1, "sets": sets}, sort_keys=False), encoding="utf-8")
    return manifest


def opener_for(responses: dict[str, bytes]):
    def opener(request, timeout: int = 30) -> Response:
        return Response(responses[request.full_url])

    return opener


def failing_opener(*_: object, **__: object) -> Response:
    raise OSError("network unavailable")


def test_domain_payload_normalizes_exact_and_suffix() -> None:
    rules = normalize_domain_payload(["example.com", "+.Example.NET", "*.example.org"])
    assert [(rule.type, rule.value) for rule in rules] == [
        ("domain", "example.com"),
        ("domain-suffix", "example.net"),
        ("domain-suffix", "example.org"),
    ]


@pytest.mark.parametrize("value", ["https://example.com", "bad domain", "example.com,REJECT"])
def test_domain_payload_rejects_non_hostname_syntax(value: str) -> None:
    with pytest.raises(UpstreamError, match="invalid domain"):
        normalize_domain_payload([value])


def test_openai_voice_rejects_empty_prefixes() -> None:
    with pytest.raises(UpstreamError, match="prefixes is empty"):
        parse_openai_voice(b'{"prefixes": []}')


def test_failed_update_preserves_existing_snapshot(tmp_path: Path) -> None:
    snapshot = tmp_path / "source/upstream/cn-domain.yaml"
    snapshot.parent.mkdir(parents=True)
    snapshot.write_text("version: 1\nrules: []\n", encoding="utf-8")
    manifest = write_manifest(tmp_path, {
        "cn-domain": {
            "parser": "domain-yaml",
            "output": "source/upstream/cn-domain.yaml",
            "urls": ["https://example.test/cn.yaml"],
        },
    })
    with pytest.raises(UpstreamError):
        sync_manifest(manifest, tmp_path, True, failing_opener)
    assert snapshot.read_text(encoding="utf-8") == "version: 1\nrules: []\n"


def test_successful_update_writes_sorted_rules_and_lock_metadata(tmp_path: Path) -> None:
    manifest = write_manifest(tmp_path, {
        "domains": {
            "parser": "domain-yaml",
            "output": "source/upstream/domains.yaml",
            "urls": ["https://example.test/domains.yaml"],
        },
    })
    result = sync_manifest(
        manifest,
        tmp_path,
        True,
        opener_for({"https://example.test/domains.yaml": b"payload: [z.example, +.A.example, z.example]\n"}),
    )
    assert result["changed"] is True
    snapshot = yaml.safe_load((tmp_path / "source/upstream/domains.yaml").read_text(encoding="utf-8"))
    assert snapshot["rules"] == [
        {"type": "domain", "value": "z.example"},
        {"type": "domain-suffix", "value": "a.example"},
    ]
    entry = json.loads((tmp_path / "source/upstream.lock.json").read_text(encoding="utf-8"))["sets"]["domains"]
    assert set(entry) == {"url", "retrieved_at", "raw_sha256", "normalized_sha256"}


def test_unchanged_update_preserves_lock_entry_despite_clock_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = write_manifest(tmp_path, {
        "domains": {
            "parser": "domain-yaml",
            "output": "source/upstream/domains.yaml",
            "urls": ["https://example.test/domains.yaml"],
        },
    })
    responses = {"https://example.test/domains.yaml": b"payload: [example.com]\n"}
    monkeypatch.setattr("scripts.lib.upstream.now_utc", lambda: "2020-01-01T00:00:00Z")
    sync_manifest(manifest, tmp_path, True, opener_for(responses))
    first_lock = (tmp_path / "source/upstream.lock.json").read_bytes()
    monkeypatch.setattr("scripts.lib.upstream.now_utc", lambda: "2030-01-01T00:00:00Z")
    result = sync_manifest(manifest, tmp_path, True, opener_for(responses))
    assert result["changed"] is False
    assert (tmp_path / "source/upstream.lock.json").read_bytes() == first_lock


def test_multi_url_set_records_each_source_hash(tmp_path: Path) -> None:
    manifest = write_manifest(tmp_path, {
        "domains": {
            "parser": "domain-yaml",
            "output": "source/upstream/domains.yaml",
            "urls": ["https://example.test/a.yaml", "https://example.test/b.yaml"],
        },
    })
    sync_manifest(manifest, tmp_path, True, opener_for({
        "https://example.test/a.yaml": b"payload: [one.example]\n",
        "https://example.test/b.yaml": b"payload: [two.example]\n",
    }))
    entry = json.loads((tmp_path / "source/upstream.lock.json").read_text(encoding="utf-8"))["sets"]["domains"]
    assert set(entry) == {"sources", "retrieved_at", "normalized_sha256"}
    assert entry["sources"] == [
        {"url": "https://example.test/a.yaml", "raw_sha256": entry["sources"][0]["raw_sha256"]},
        {"url": "https://example.test/b.yaml", "raw_sha256": entry["sources"][1]["raw_sha256"]},
    ]


def test_unchanged_multi_url_update_preserves_set_timestamp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = write_manifest(tmp_path, {
        "domains": {
            "parser": "domain-yaml",
            "output": "source/upstream/domains.yaml",
            "urls": ["https://example.test/a.yaml", "https://example.test/b.yaml"],
        },
    })
    responses = {
        "https://example.test/a.yaml": b"payload: [one.example]\n",
        "https://example.test/b.yaml": b"payload: [two.example]\n",
    }
    monkeypatch.setattr("scripts.lib.upstream.now_utc", lambda: "2020-01-01T00:00:00Z")
    sync_manifest(manifest, tmp_path, True, opener_for(responses))
    first_lock = (tmp_path / "source/upstream.lock.json").read_bytes()
    monkeypatch.setattr("scripts.lib.upstream.now_utc", lambda: "2030-01-01T00:00:00Z")
    result = sync_manifest(manifest, tmp_path, True, opener_for(responses))
    assert result["changed"] is False
    assert (tmp_path / "source/upstream.lock.json").read_bytes() == first_lock


def test_update_migrates_legacy_multi_url_lock_without_timestamp(tmp_path: Path) -> None:
    manifest = write_manifest(tmp_path, {
        "domains": {
            "parser": "domain-yaml",
            "output": "source/upstream/domains.yaml",
            "urls": ["https://example.test/a.yaml", "https://example.test/b.yaml"],
        },
    })
    responses = {
        "https://example.test/a.yaml": b"payload: [one.example]\n",
        "https://example.test/b.yaml": b"payload: [two.example]\n",
    }
    sync_manifest(manifest, tmp_path, True, opener_for(responses))
    lock_path = tmp_path / "source/upstream.lock.json"
    legacy_lock = json.loads(lock_path.read_text(encoding="utf-8"))
    legacy_lock["sets"]["domains"].pop("retrieved_at")
    lock_path.write_text(json.dumps(legacy_lock), encoding="utf-8")

    result = sync_manifest(manifest, tmp_path, True, opener_for(responses))

    assert result["changed"] is True
    assert json.loads(lock_path.read_text(encoding="utf-8"))["sets"]["domains"]["retrieved_at"]


def test_check_mode_reports_changes_without_writing(tmp_path: Path) -> None:
    manifest = write_manifest(tmp_path, {
        "domains": {
            "parser": "domain-yaml",
            "output": "source/upstream/domains.yaml",
            "urls": ["https://example.test/domains.yaml"],
        },
    })
    responses = {"https://example.test/domains.yaml": b"payload: [example.com]\n"}
    sync_manifest(manifest, tmp_path, True, opener_for(responses))
    before = (tmp_path / "source/upstream/domains.yaml").read_bytes()
    result = sync_manifest(manifest, tmp_path, False, opener_for({
        "https://example.test/domains.yaml": b"payload: [changed.example]\n",
    }))
    assert result["changed"] is True
    assert (tmp_path / "source/upstream/domains.yaml").read_bytes() == before


def test_write_failure_rolls_back_all_snapshots_and_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest = write_manifest(tmp_path, {
        "a": {"parser": "domain-yaml", "output": "source/upstream/a.yaml", "urls": ["https://example.test/a.yaml"]},
        "b": {"parser": "domain-yaml", "output": "source/upstream/b.yaml", "urls": ["https://example.test/b.yaml"]},
    })
    initial = {
        "https://example.test/a.yaml": b"payload: [first.example]\n",
        "https://example.test/b.yaml": b"payload: [second.example]\n",
    }
    sync_manifest(manifest, tmp_path, True, opener_for(initial))
    tracked = [
        tmp_path / "source/upstream/a.yaml",
        tmp_path / "source/upstream/b.yaml",
        tmp_path / "source/upstream.lock.json",
    ]
    before = {path: path.read_bytes() for path in tracked}
    original_replace = __import__("scripts.lib.upstream", fromlist=["os"]).os.replace
    calls = 0

    def fail_second_replace(source: Path, destination: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("injected replace failure")
        original_replace(source, destination)

    monkeypatch.setattr("scripts.lib.upstream.os.replace", fail_second_replace)
    changed = {
        "https://example.test/a.yaml": b"payload: [changed-first.example]\n",
        "https://example.test/b.yaml": b"payload: [changed-second.example]\n",
    }
    with pytest.raises(UpstreamError, match="failed to write upstream snapshots"):
        sync_manifest(manifest, tmp_path, True, opener_for(changed))
    assert {path: path.read_bytes() for path in tracked} == before


def test_sync_script_runs_directly_from_repository_root() -> None:
    repo_root = Path(__file__).parents[1]
    result = subprocess.run(
        [sys.executable, "scripts/sync_upstreams.py", "--help"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
