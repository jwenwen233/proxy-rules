from pathlib import Path

from scripts.lib.generate import (
    build_all,
    choose_mihomo_behavior,
    render_mihomo,
    render_shadowrocket,
)
from scripts.lib.model import Rule


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
