# Personal Proxy Rules

This repository publishes only reusable rules and client configuration templates. Airport
subscriptions and nodes stay local to your device: do not commit, paste, or publish them
here.

## Shadowrocket 安装

1. Import your airport subscription into Shadowrocket and test that a node can connect.
2. Import [`configs/shadowrocket.conf`](configs/shadowrocket.conf).
3. In `PRX-Manual`, select a usable node, or let `PRX-Auto` test the imported nodes.
4. Enable the imported rule/config profile. The configuration preserves UDP and does not
   disable WebRTC.

## Clash Verge Rev 安装

1. Import your airport subscription into Clash Verge Rev and test that a node can connect.
2. Paste [`configs/clash-verge-script.js`](configs/clash-verge-script.js) into Global Script.
3. In `PRX-Manual`, select a usable node, or let `PRX-Auto` test the imported nodes.
4. Enable rule/config mode. Enable TUN manually only when you want full-device traffic
   capture; Global Script does not change the existing TUN setting. The configuration
   preserves UDP and does not disable WebRTC.

## 更换机场

Replace and test the local subscription first, then choose a usable node in `PRX-Manual` or
allow `PRX-Auto` to test it. Do not edit public configuration files: subscriptions and nodes
remain local and are never part of this repository.

## DNS 检测结果怎么读

Cloudflare resolver IPs may geolocate to multiple anycast cities. That alone is expected and
is not an ISP DNS leak. The failure signal is a resolver owned by your mobile or broadband
ISP. Test while the selected proxy profile is active so that the result reflects the profile
rather than an earlier local lookup.

## WebRTC 检测结果怎么读

Different proxy-owned HTTP and STUN IPs can mean the provider uses separate TCP and UDP
egress; that is not itself a leak. A local ISP public IP reported by STUN is a real leak.
These configurations intentionally preserve WebRTC and UDP, so the appropriate check is
whether STUN exposes the local ISP address, not whether WebRTC is disabled.

## 回滚

Disable Clash Verge Rev Global Script or the selected Shadowrocket configuration, restore your
previous profile, and leave the subscription untouched. Your nodes and subscription remain
local throughout rollback.

## 本地验证

Run the reproducibility and repository checks before publishing changes:

```sh
python3 scripts/build_rules.py --check
python3 scripts/validate.py
```

For the complete local gate, install the development dependencies, run `pytest -q`, and run
`node --test tests/test_clash_script.cjs` as well.

## 上游与致谢

Rules and configuration choices draw on the services and projects below. Exact synchronized
upstream URLs and hashes are tracked in `source/upstreams.yaml` and `source/upstream.lock.json`.

- [MetaCubeX meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) supplies normalized
  domain and IP snapshots; that repository is GPL-3.0.
- [OpenAI network recommendations](https://help.openai.com/en/articles/9247338-network-recommendations-for-chatgpt-errors-on-web-and-apps)
  inform the canonical OpenAI domains, while the exact voice IP data is synchronized from
  [OpenAI's voice JSON](https://openai.com/chatgpt-voice.json).
- [Claude Code corporate proxy documentation](https://code.claude.com/docs/en/corporate-proxy)
  is authoritative for the core Claude Code network families used by the canonical list.
  [Anthropic](https://www.anthropic.com/) remains the service homepage. The user-provided
  [Claude site list](https://ip.net.coffee/claude/site.html) is a supplemental community/manual reference, not an official Anthropic policy.
- [Mihomo](https://github.com/MetaCubeX/mihomo) validates the generated proxy configuration;
  [Clash Verge Rev](https://github.com/clash-verge-rev/clash-verge-rev) hosts the Global Script;
  and the [Shadowrocket community manual](https://github.com/h2y/Shadowrocket-ADBlock-Rules/wiki)
  explains client configuration. Their licenses are not asserted here.

Repository-authored content and GPL-compatible incorporated outputs are licensed under
[GPL-3.0](LICENSE).
