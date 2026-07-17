from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from ipaddress import ip_network
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Callable
from urllib.request import Request, urlopen

import yaml

from scripts.lib.model import Rule


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
    try:
        result = {Rule("ip-cidr", str(ip_network(value, strict=False))) for value in payload}
    except (TypeError, ValueError) as error:
        raise UpstreamError(f"invalid upstream IP prefix: {error}") from error
    return sorted(result, key=lambda rule: rule.value)


def parse_openai_voice(raw: bytes) -> list[Rule]:
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise UpstreamError(f"invalid OpenAI voice JSON: {error}") from error
    prefixes = data.get("prefixes") if isinstance(data, dict) else None
    if not isinstance(prefixes, list) or not prefixes:
        raise UpstreamError("OpenAI voice prefixes is empty")
    values = []
    for item in prefixes:
        if not isinstance(item, dict):
            raise UpstreamError("OpenAI voice prefix entry has no IP prefix")
        value = item.get("ipv4Prefix") or item.get("ipv6Prefix")
        if not value:
            raise UpstreamError("OpenAI voice prefix entry has no IP prefix")
        values.append(value)
    return normalize_ip_payload(values)


def render_snapshot(rules: list[Rule]) -> bytes:
    data = {"version": 1, "rules": [{"type": rule.type, "value": rule.value} for rule in rules]}
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=False).encode()


def now_utc() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def default_opener(request: Request, timeout: int = 30):
    return urlopen(request, timeout=timeout)


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _load_manifest(path: Path) -> dict[str, dict[str, object]]:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise UpstreamError(f"cannot read upstream manifest: {error}") from error
    sets = data.get("sets") if isinstance(data, dict) and data.get("version") == 1 else None
    if not isinstance(sets, dict) or not sets:
        raise UpstreamError("upstream manifest must contain a non-empty sets mapping")
    for name, config in sets.items():
        if not isinstance(name, str) or not isinstance(config, dict):
            raise UpstreamError("upstream manifest contains an invalid set")
        if config.get("parser") not in {"domain-yaml", "ip-yaml", "openai-voice-json"}:
            raise UpstreamError(f"{name}: unsupported upstream parser")
        if not isinstance(config.get("output"), str):
            raise UpstreamError(f"{name}: output must be a path")
        urls = config.get("urls")
        if not isinstance(urls, list) or not urls or not all(isinstance(url, str) and url for url in urls):
            raise UpstreamError(f"{name}: urls must be a non-empty list")
    return sets


def _load_lock(path: Path) -> dict[str, object]:
    if not path.exists():
        return {"version": 1, "sets": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise UpstreamError(f"cannot read upstream lock: {error}") from error
    if not isinstance(data, dict) or data.get("version") != 1 or not isinstance(data.get("sets"), dict):
        raise UpstreamError("upstream lock must contain version 1 and a sets mapping")
    return data


def _parse_yaml_payload(raw: bytes, parser: str, name: str) -> list[Rule]:
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as error:
        raise UpstreamError(f"{name}: invalid upstream YAML: {error}") from error
    payload = data.get("payload") if isinstance(data, dict) else None
    if not isinstance(payload, list) or not payload:
        raise UpstreamError(f"{name}: upstream YAML payload must be a non-empty list")
    if parser == "domain-yaml":
        return normalize_domain_payload(payload)
    return normalize_ip_payload(payload)


def _fetch(url: str, opener: Callable) -> bytes:
    request = Request(url, headers={"User-Agent": "jwenwen233/proxy-rules"})
    try:
        with opener(request, timeout=30) as response:
            return response.read()
    except Exception as error:
        raise UpstreamError(f"failed to download {url}: {error}") from error


def _same_sources(entry: object, source_hashes: list[dict[str, str]]) -> bool:
    if not isinstance(entry, dict):
        return False
    if len(source_hashes) == 1:
        return entry.get("url") == source_hashes[0]["url"] and entry.get("raw_sha256") == source_hashes[0]["raw_sha256"]
    return entry.get("sources") == source_hashes


def _new_lock_entry(source_hashes: list[dict[str, str]], normalized_sha256: str) -> dict[str, object]:
    if len(source_hashes) == 1:
        return {
            "url": source_hashes[0]["url"],
            "retrieved_at": now_utc(),
            "raw_sha256": source_hashes[0]["raw_sha256"],
            "normalized_sha256": normalized_sha256,
        }
    return {"sources": source_hashes, "normalized_sha256": normalized_sha256}


def _write_atomically(files: dict[Path, bytes]) -> None:
    temporary: list[tuple[Path, Path]] = []
    backups: dict[Path, Path | None] = {}
    replaced: list[Path] = []
    try:
        for destination, content in files.items():
            destination.parent.mkdir(parents=True, exist_ok=True)
            with NamedTemporaryFile("wb", dir=destination.parent, delete=False) as handle:
                handle.write(content)
                temporary.append((Path(handle.name), destination))
            if destination.exists():
                with NamedTemporaryFile("wb", dir=destination.parent, delete=False) as handle:
                    handle.write(destination.read_bytes())
                    backups[destination] = Path(handle.name)
            else:
                backups[destination] = None
        for temporary_path, destination in temporary:
            os.replace(temporary_path, destination)
            replaced.append(destination)
    except OSError as error:
        try:
            for destination in reversed(replaced):
                backup = backups[destination]
                if backup is None:
                    destination.unlink(missing_ok=True)
                else:
                    os.replace(backup, destination)
        except OSError as rollback_error:
            raise UpstreamError(f"failed to write upstream snapshots and roll back: {rollback_error}") from error
        raise UpstreamError(f"failed to write upstream snapshots: {error}") from error
    finally:
        for temporary_path, _ in temporary:
            if temporary_path.exists():
                temporary_path.unlink()
        for backup in backups.values():
            if backup is not None and backup.exists():
                backup.unlink()


def sync_manifest(manifest: Path, repo_root: Path, update: bool, opener: Callable) -> dict:
    sets = _load_manifest(manifest)
    lock_path = repo_root / "source/upstream.lock.json"
    existing_lock = _load_lock(lock_path)
    existing_sets = existing_lock["sets"]
    assert isinstance(existing_sets, dict)

    prepared_files: dict[Path, bytes] = {}
    next_sets: dict[str, object] = {}
    changed = False
    for name in sorted(sets):
        config = sets[name]
        parser = config["parser"]
        output = config["output"]
        urls = config["urls"]
        assert isinstance(parser, str) and isinstance(output, str) and isinstance(urls, list)
        destination = (repo_root / output).resolve()
        if repo_root.resolve() not in destination.parents:
            raise UpstreamError(f"{name}: output escapes repository root")

        rules: set[Rule] = set()
        source_hashes: list[dict[str, str]] = []
        for url in urls:
            assert isinstance(url, str)
            raw = _fetch(url, opener)
            source_hashes.append({"url": url, "raw_sha256": _sha256(raw)})
            parsed = parse_openai_voice(raw) if parser == "openai-voice-json" else _parse_yaml_payload(raw, parser, name)
            rules.update(parsed)
        normalized_rules = sorted(rules, key=lambda rule: (rule.type, rule.value))
        snapshot = render_snapshot(normalized_rules)
        normalized_sha256 = _sha256(snapshot)
        prepared_files[destination] = snapshot
        existing_entry = existing_sets.get(name)
        unchanged = (
            _same_sources(existing_entry, source_hashes)
            and isinstance(existing_entry, dict)
            and existing_entry.get("normalized_sha256") == normalized_sha256
            and destination.exists()
            and destination.read_bytes() == snapshot
        )
        if unchanged:
            next_sets[name] = existing_entry
        else:
            next_sets[name] = _new_lock_entry(source_hashes, normalized_sha256)
            changed = True

    if set(existing_sets) != set(sets):
        changed = True
    next_lock = {"version": 1, "sets": next_sets}
    lock_bytes = (json.dumps(next_lock, indent=2, sort_keys=False) + "\n").encode()
    if not lock_path.exists() or lock_path.read_bytes() != lock_bytes:
        changed = True
    if update and changed:
        files = {path: content for path, content in prepared_files.items() if not path.exists() or path.read_bytes() != content}
        files[lock_path] = lock_bytes
        _write_atomically(files)
    return {"changed": changed, "sets": next_sets}
