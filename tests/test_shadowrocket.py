from __future__ import annotations

from pathlib import Path
import re


CONFIG = Path(__file__).parents[1] / "configs/shadowrocket.conf"
RAW_PREFIX = "https://raw.githubusercontent.com/jwenwen233/proxy-rules/main/dist/shadowrocket/"
INFO_FILTER = (
    "^((?!(剩余|流量|套餐|到期|官网|更新|订阅|客服|Expire|Traffic|Website)).)*$"
)


def _sections() -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for raw_line in CONFIG.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = sections.setdefault(line[1:-1], [])
        elif current is not None:
            current.append(line)
    return sections


def _general(lines: list[str]) -> dict[str, str]:
    return dict(line.split(" = ", 1) for line in lines)


def _groups(lines: list[str]) -> dict[str, list[str]]:
    return {
        name: [item.strip() for item in details.split(",")]
        for name, details in (line.split(" = ", 1) for line in lines)
    }


def _index(rules: list[str], rule: str) -> int:
    return rules.index(rule)


def test_general_uses_proxied_browsing_dns_and_reachable_node_bootstrap():
    general = _general(_sections()["General"])

    assert general["dns-server"] == "https://1.1.1.1/dns-query#proxy"
    assert general["fallback-dns-server"] == "https://1.0.0.1/dns-query#proxy"
    assert general["proxy-dns-server"] == "223.5.5.5"
    assert general["dns-direct-system"] == "false"
    assert general["ipv6"] == "false"
    assert general["prefer-ipv6"] == "false"
    assert general["always-ip-address"] == "true"
    assert general["udp-policy-not-supported-behaviour"] == "REJECT"
    assert "system" not in general["dns-server"]
    assert "system" not in general["fallback-dns-server"]
    assert "dns-fallback-system" not in general


def test_groups_are_complete_and_stably_ordered():
    groups = _groups(_sections()["Proxy Group"])
    assert list(groups) == [
        "PRX-Manual",
        "PRX-Auto",
        "PRX-AI",
        "PRX-Media",
        "PRX-Messaging",
        "PRX-Apple-Microsoft",
        "PRX-Proxy",
    ]
    assert groups["PRX-Manual"] == ["select", f"policy-regex-filter={INFO_FILTER}"]
    assert groups["PRX-Auto"] == [
        "url-test",
        f"policy-regex-filter={INFO_FILTER}",
        "url=https://www.gstatic.com/generate_204",
        "interval=600",
    ]
    assert groups["PRX-AI"] == ["select", "PRX-Manual", "PRX-Auto"]
    assert groups["PRX-Media"] == ["select", "PRX-Manual", "PRX-Auto"]
    assert groups["PRX-Messaging"] == ["select", "PRX-Manual", "PRX-Auto"]
    assert groups["PRX-Apple-Microsoft"] == [
        "select", "DIRECT", "PRX-Manual", "PRX-Auto",
    ]
    assert groups["PRX-Proxy"] == ["select", "PRX-Manual", "PRX-Auto"]
    assert "DIRECT" not in groups["PRX-AI"]


def test_rules_preserve_critical_precedence_and_safe_final_routing():
    rules = _sections()["Rule"]
    embedded_ai = [
        "DOMAIN-SUFFIX,anthropic.com,PRX-AI",
        "DOMAIN-SUFFIX,claude.ai,PRX-AI",
        "DOMAIN-SUFFIX,claude.com,PRX-AI",
        "DOMAIN-SUFFIX,openai.com,PRX-AI",
        "DOMAIN-SUFFIX,chatgpt.com,PRX-AI",
        "DOMAIN-SUFFIX,oaistatic.com,PRX-AI",
        "DOMAIN-SUFFIX,oaiusercontent.com,PRX-AI",
    ]
    remote_ai = f"RULE-SET,{RAW_PREFIX}ai.list,PRX-AI"
    remote_media = f"RULE-SET,{RAW_PREFIX}media.list,PRX-Media"
    remote_messaging = f"RULE-SET,{RAW_PREFIX}messaging.list,PRX-Messaging"
    remote_cn = f"RULE-SET,{RAW_PREFIX}cn.list,DIRECT"

    first_remote_provider = min(
        index for index, rule in enumerate(rules) if rule.startswith("RULE-SET,")
    )
    assert all(_index(rules, rule) < first_remote_provider for rule in embedded_ai)
    assert _index(rules, remote_cn) > _index(rules, remote_ai)
    assert _index(rules, remote_cn) > _index(rules, remote_media)
    assert _index(rules, remote_cn) > _index(rules, remote_messaging)
    assert rules[-2:] == ["GEOIP,CN,DIRECT", "FINAL,PRX-Proxy"]


def test_config_is_node_free_and_uses_only_public_repository_rule_urls():
    text = CONFIG.read_text(encoding="utf-8")
    sections = _sections()

    assert "[Proxy]" not in text
    assert "Proxy" not in sections
    assert not {"MITM", "Certificate", "Host", "URL Rewrite"} & set(sections)
    assert not re.search(
        r"(?im)^\s*(?:vless|vmess|trojan|ss|ssr|hysteria2?|tuic|shadowsocks):",
        text,
    )
    assert "subscription" not in text.lower()
    assert not re.search(r"(?im)^\s*(?:uuid|password|private-key|reality-opts)\s*=", text)
    rule_urls = [
        line.split(",")[1]
        for line in sections["Rule"]
        if line.startswith("RULE-SET,")
    ]
    assert rule_urls
    assert all(url.startswith(RAW_PREFIX) for url in rule_urls)
    generated_dir = CONFIG.parents[1] / "dist/shadowrocket"
    missing_files = [
        generated_dir / url.removeprefix(RAW_PREFIX)
        for url in rule_urls
        if not (generated_dir / url.removeprefix(RAW_PREFIX)).is_file()
    ]
    assert not missing_files, f"missing generated rule files: {missing_files}"
