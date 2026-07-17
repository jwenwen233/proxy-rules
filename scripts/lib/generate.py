from __future__ import annotations

from collections.abc import Iterable, Sequence
from pathlib import Path

import yaml

from scripts.lib.model import Rule, load_rule_file, rules_for_target

SHADOWROCKET_TYPES = {
    "domain": "DOMAIN",
    "domain-suffix": "DOMAIN-SUFFIX",
    "domain-keyword": "DOMAIN-KEYWORD",
    "ip-cidr": "IP-CIDR",
    "ip-asn": "IP-ASN",
}
MIHOMO_CLASSICAL_TYPES = {**SHADOWROCKET_TYPES, "process-name": "PROCESS-NAME"}


def _sorted_rules(rules: Iterable[Rule], target: str) -> list[Rule]:
    return sorted(rules_for_target(rules, target), key=lambda rule: (rule.type, rule.value))


def render_shadowrocket(rules: Iterable[Rule]) -> str:
    lines = []
    for rule in _sorted_rules(rules, "shadowrocket"):
        suffix = ",no-resolve" if rule.type in {"ip-cidr", "ip-asn"} else ""
        lines.append(f"{SHADOWROCKET_TYPES[rule.type]},{rule.value}{suffix}")
    return "\n".join(lines) + ("\n" if lines else "")


def choose_mihomo_behavior(rules: Sequence[Rule]) -> str:
    types = {rule.type for rule in rules_for_target(rules, "mihomo")}
    if types <= {"domain", "domain-suffix"}:
        return "domain"
    if types == {"ip-cidr"}:
        return "ipcidr"
    return "classical"


def render_mihomo(rules: Sequence[Rule], behavior: str) -> str:
    selected = _sorted_rules(rules, "mihomo")
    if behavior == "domain":
        payload = [rule.value if rule.type == "domain" else f"+.{rule.value}" for rule in selected]
    elif behavior == "ipcidr":
        payload = [rule.value for rule in selected]
    elif behavior == "classical":
        payload = [
            f"{MIHOMO_CLASSICAL_TYPES[rule.type]},{rule.value}"
            + (",no-resolve" if rule.type in {"ip-cidr", "ip-asn"} else "")
            for rule in selected
        ]
    else:
        raise ValueError(f"unsupported Mihomo behavior: {behavior}")
    return yaml.safe_dump({"payload": payload}, allow_unicode=True, default_flow_style=False, sort_keys=False)


def _rules_from(repo_root: Path, *sources: str) -> list[Rule]:
    rules: list[Rule] = []
    for source in sources:
        rules.extend(load_rule_file(repo_root / source))
    return rules


MIHOMO_SETS = {
    "direct": ("source/personal/direct.yaml",),
    "reject-domain": ("source/personal/reject.yaml", "source/upstream/reject-domain.yaml"),
    "ai": ("source/ai/anthropic.yaml", "source/ai/openai.yaml"),
    "openai-voice-ip": ("source/ai/openai-voice.yaml",),
    "media": ("source/upstream/media-domain.yaml",),
    "messaging": ("source/upstream/messaging-domain.yaml",),
    "apple-microsoft": ("source/upstream/apple-microsoft-domain.yaml",),
    "cn-domain": ("source/upstream/cn-domain.yaml",),
    "cn-ip": ("source/upstream/cn-ip.yaml",),
}

SHADOWROCKET_SETS = {
    "direct": MIHOMO_SETS["direct"],
    "reject-domain": MIHOMO_SETS["reject-domain"],
    "ai": (*MIHOMO_SETS["ai"], *MIHOMO_SETS["openai-voice-ip"]),
    "media": MIHOMO_SETS["media"],
    "messaging": MIHOMO_SETS["messaging"],
    "apple-microsoft": MIHOMO_SETS["apple-microsoft"],
    "cn": (*MIHOMO_SETS["cn-domain"], *MIHOMO_SETS["cn-ip"]),
}


def build_all(repo_root: Path) -> dict[Path, str]:
    repo_root = repo_root.resolve()
    rendered: dict[Path, str] = {}
    for name, sources in sorted(SHADOWROCKET_SETS.items()):
        rendered[repo_root / "dist/shadowrocket" / f"{name}.list"] = render_shadowrocket(_rules_from(repo_root, *sources))
    for name, sources in sorted(MIHOMO_SETS.items()):
        rules = _rules_from(repo_root, *sources)
        rendered[repo_root / "dist/mihomo" / f"{name}.yaml"] = render_mihomo(rules, choose_mihomo_behavior(rules))
    return rendered
