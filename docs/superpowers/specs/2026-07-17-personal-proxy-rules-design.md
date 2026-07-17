# Personal Proxy Rules Repository Design

Date: 2026-07-17

Target repository: `https://github.com/jwenwen233/proxy-rules`

## 1. Purpose

Build a public, reusable rules repository for Shadowrocket and Clash Verge Rev/Mihomo. The repository owns DNS behavior, routing rules, policy groups, generated rule formats, validation, and documentation. Proxy nodes and airport subscription URLs remain local to each client and never enter the repository.

The configuration must continue to work when the user changes airport providers. China traffic is direct, non-China traffic defaults to proxy, advertising and known malicious destinations are rejected, IPv6 is disabled, and DNS queries for ordinary browsing are encrypted and routed through the selected proxy.

## 2. Confirmed Product Decisions

- Routing model: China direct, overseas proxy, advertising rejected.
- Nodes: imported separately; configuration files do not contain nodes or subscription URLs.
- DNS model: strict privacy. Ordinary domain resolution uses Cloudflare DoH through the selected proxy, with no system DNS fallback.
- UDP model: preserve UDP, voice, video, games, and QUIC. UDP is routed through the selected proxy when the node supports it. If a node cannot proxy UDP, reject rather than silently fall back to direct.
- IPv6: disabled in both client configurations.
- Distribution: public GitHub repository.
- Rule maintenance: canonical local sources plus automated upstream synchronization and generated client-specific outputs.
- Policy complexity: balanced groups for default proxy, AI, streaming, messaging, and Apple/Microsoft.
- Existing personal exceptions: preserve ToDesk and `scnet.cn` direct routing.

## 3. Non-Goals

- Store or publish proxy credentials, VLESS UUIDs, private keys, subscription URLs, or provider account details.
- Force an airport provider's TCP and UDP traffic to use the same public egress IP. A client configuration cannot merge provider-side NAT pools.
- Disable WebRTC or block all UDP.
- Route all NTP traffic through the proxy. NTP returns UTC time rather than the operating-system timezone; forcing it through arbitrary proxy nodes can impair clock synchronization.
- Perform HTTPS interception or install a local CA certificate.

## 4. Repository Layout

```text
proxy-rules/
├── source/
│   ├── personal/
│   │   ├── direct.yaml
│   │   ├── proxy.yaml
│   │   └── reject.yaml
│   ├── ai/
│   │   ├── anthropic.yaml
│   │   ├── openai.yaml
│   │   └── openai-voice.yaml
│   └── upstream.lock.json
├── dist/
│   ├── shadowrocket/
│   │   ├── direct.list
│   │   ├── reject.list
│   │   ├── ai.list
│   │   ├── media.list
│   │   ├── messaging.list
│   │   ├── apple-microsoft.list
│   │   └── cn.list
│   └── mihomo/
│       ├── direct.yaml
│       ├── reject.yaml
│       ├── ai.yaml
│       ├── openai-voice.yaml
│       ├── media.yaml
│       ├── messaging.yaml
│       ├── apple-microsoft.yaml
│       └── cn.yaml
├── configs/
│   ├── shadowrocket.conf
│   └── clash-verge-merge.js
├── scripts/
│   ├── sync_upstreams.py
│   ├── build_rules.py
│   └── validate.py
├── tests/
│   ├── fixtures/
│   ├── test_generation.py
│   ├── test_precedence.py
│   └── test_secrets.py
├── .github/workflows/
│   └── validate.yml
├── LICENSE
└── README.md
```

## 5. Canonical Rule Model

Canonical YAML records use an explicit rule type and value rather than client-specific syntax:

```yaml
rules:
  - type: domain-suffix
    value: anthropic.com
  - type: domain
    value: browser-intake-us5-datadoghq.com
  - type: ip-cidr
    value: 160.79.104.0/21
```

Supported canonical types are `domain`, `domain-suffix`, `domain-keyword`, `ip-cidr`, `ip-asn`, and `process-name`. Generation converts the same canonical record into Shadowrocket list syntax and Mihomo rule-provider YAML.

Broad `domain-keyword` entries are disallowed by default because they commonly route unrelated sites. A keyword requires an explicit allow entry in the validator configuration and a comment explaining the scope.

## 6. Upstream Sources and Licensing

The repository is licensed GPL-3.0 and preserves source attribution in the README and lock file.

- MetaCubeX `meta-rules-dat` supplies maintained CN, advertising, media, messaging, Apple, and Microsoft datasets.
- Anthropic's official Claude Code enterprise network documentation is authoritative for Claude and Claude Code destinations.
- OpenAI's official ChatGPT network recommendations are authoritative for ChatGPT, OpenAI, WebSocket, file, app, and voice destinations.
- Net.Coffee's Claude list is supplemental. Entries are accepted only when they do not create an unsafe broad match and are not contradicted by official documentation.

`sync_upstreams.py` records the upstream URL, retrieval timestamp, and content SHA-256 in `source/upstream.lock.json`. Generated output is reproducible from the locked inputs.

## 7. Policy Groups

Both clients expose equivalent logical groups:

- `Manual`: all usable imported nodes, excluding quota, expiry, website, and informational entries.
- `Auto`: URL-test over all usable imported nodes.
- `AI`: select between `Manual` and `Auto`; no `DIRECT` option.
- `Media`: select between `Manual` and `Auto`.
- `Messaging`: select between `Manual` and `Auto`.
- `Apple-Microsoft`: select between `DIRECT`, `Manual`, and `Auto`; default is `DIRECT`.
- `Proxy`: select between `Manual` and `Auto`; this is the final overseas policy.

The generated files may display localized emoji names, but internal generation and tests use stable ASCII identifiers. The Clash enhancement script discovers proxies and proxy providers from the active airport profile and rebuilds these groups without copying credentials. The Shadowrocket configuration uses dynamic policy filters so separately imported nodes remain available after changing subscriptions.

## 8. Rule Precedence

Rules are evaluated in this fixed order:

1. Loopback, LAN, private ranges, captive portal, and essential system connectivity: `DIRECT`.
2. ToDesk processes/domains and `scnet.cn`: `DIRECT`.
3. Advertising, tracking, hijacking, and known malicious destinations: `REJECT`.
4. Claude, Anthropic, ChatGPT, OpenAI, and their required exact infrastructure destinations: `AI`.
5. Telegram and Discord: `Messaging`.
6. Streaming services: `Media`.
7. Apple and Microsoft: `Apple-Microsoft`.
8. China domains and China IP ranges: `DIRECT`.
9. Everything else: `Proxy`.

IP rules use `no-resolve` where supported. Domain rules precede IP rules. The final policy is always proxy rather than direct.

## 9. AI Rules

### Anthropic and Claude

The AI set includes the official core families and specific supplemental endpoints, including:

- `anthropic.com`
- `claude.ai`
- `claude.com`
- `clau.de`
- `claudemcpclient.com`
- `claudemcpcontent.com`
- `claudeusercontent.com`
- Exact CDN, authentication, telemetry, and content endpoints that are verified as Anthropic dependencies
- Anthropic-owned IPv4/ASN fallback records when independently verified

Shared infrastructure such as all of `sentry.io`, all Datadog domains, all Intercom domains, `storage.googleapis.com`, and `raw.githubusercontent.com` is not assigned to AI by a broad keyword. It is still proxied by the final `Proxy` policy. Exact endpoints may be assigned to AI when official documentation identifies them.

### OpenAI and ChatGPT

The AI set includes official OpenAI families and exact dependencies, including:

- `openai.com`
- `chatgpt.com`
- `auth.openai.com`
- `oaistatic.com`
- `oaiusercontent.com`
- `oaistatsig.com`
- Official authentication, WorkOS, app, WebSocket, upload, and exact telemetry endpoints

ChatGPT Voice IP ranges are synchronized from OpenAI's maintained `chatgpt-voice.json` and routed to `AI` for UDP port 3478. If the voice list cannot update, the previous validated list remains in `dist`; the build does not replace it with an empty file.

## 10. DNS and Leak Prevention

### Shadowrocket

- Primary and fallback DNS: Cloudflare DoH with `#proxy`.
- `dns-direct-system = false`.
- `dns-fallback-system = false`.
- `ipv6 = false` and `prefer-ipv6 = false`.
- Hard-coded common DNS destinations are hijacked where supported.
- Node hostname bootstrap uses encrypted DoH without system DNS.
- Unsupported UDP behavior is `REJECT`, preventing silent direct fallback while retaining UDP for capable nodes.

### Clash Verge Rev/Mihomo

The global enhancement script overrides DNS and relevant TUN fields while preserving application-controlled ports and service settings:

- DNS enabled, IPv6 disabled, `fake-ip` enhanced mode.
- `respect-rules: true`.
- TUN DNS hijack includes `any:53`.
- Ordinary nameservers and fallback use Cloudflare DoH explicitly routed through `Proxy`.
- No system nameserver is configured.
- Proxy-server hostname bootstrap uses direct encrypted DoH to an IP-addressed resolver, avoiding a circular dependency before a proxy connection exists.
- Fake-IP exclusions are limited to LAN discovery, captive portal, STUN-sensitive, and service-discovery names that require real addresses.

Bootstrap DNS is a necessary exception for airport nodes whose server is specified by hostname: the proxy hostname must be resolved before a proxy tunnel exists. This bootstrap is encrypted and restricted to proxy-server hostnames. Ordinary website DNS continues through the proxy.

The merge script does not force-enable TUN; the user controls the TUN switch in Clash Verge. When TUN is enabled, the DNS hijack prevents applications from bypassing Mihomo with hard-coded port-53 resolvers.

## 11. UDP and WebRTC

UDP-capable nodes receive UDP traffic through the same selected policy. The configuration does not reject WebRTC, ChatGPT Voice, conferencing, games, or QUIC.

If a provider intentionally uses different TCP and UDP NAT pools, WebRTC tests can report two proxy egress IPs. This is not a local-IP bypass and cannot be corrected by client routing rules. The README explains how to distinguish provider-side split egress from a real local ISP leak.

## 12. Failure Handling

- Rule providers update every 24 hours and retain the last valid cache.
- Upstream sync uses timeouts, schema checks, non-empty checks, and SHA-256 locking.
- A failed or empty upstream never overwrites the last known-good generated file.
- Critical LAN, AI, and final-routing rules are embedded in the client configuration so a first-run provider download failure cannot send AI traffic direct.
- A missing policy group, unknown rule type, invalid IP, malformed domain, duplicate conflicting rule, or unresolved repository URL fails validation.
- DNS failure produces a resolution failure rather than system-DNS fallback.

## 13. Security Controls

Validation rejects commits containing:

- `vless://`, `vmess://`, `trojan://`, `ss://`, or subscription installation URIs
- UUID/private-key patterns and Reality private-key fields
- URL query parameters commonly used by airport subscriptions
- YAML proxy credential keys in source, dist, configuration, and documentation files

The secret scanner uses both pattern matching and an allowlist for harmless documentation examples. GitHub Actions receives no subscription secret.

## 14. Testing

Automated tests cover:

- Canonical-to-Shadowrocket conversion.
- Canonical-to-Mihomo conversion.
- Stable, deterministic output.
- Duplicate and conflict detection.
- Rule precedence and policy existence.
- Claude and ChatGPT representative domains map to `AI`.
- CN and private destinations map to `DIRECT`.
- Advertising samples map to `REJECT`.
- Unknown overseas domains reach final `Proxy`.
- IPv6 and system-DNS fallback remain disabled.
- No secrets exist in tracked files.
- A fixture airport profile is enhanced without losing its proxies or proxy providers.
- Mihomo validates a composed fixture configuration with its configuration-test command.

Shadowrocket has no supported desktop CLI validator, so its tests parse sections, validate supported rule syntax, validate policy references, and compare generated records against golden fixtures. Final device verification is documented as a manual acceptance test.

## 15. Manual Acceptance Test

For each client:

1. Import a test airport subscription separately.
2. Apply the generated configuration/enhancement.
3. Confirm policy groups contain imported nodes.
4. Confirm Claude and ChatGPT use `AI`.
5. Confirm a representative CN site is direct and an unknown overseas site is proxied.
6. Confirm ad samples are rejected.
7. Confirm public HTTP egress matches the selected proxy.
8. Run DNS leak detection and verify no mobile/broadband ISP resolver appears.
9. Run WebRTC detection and distinguish local-IP leakage from provider-side UDP split egress.
10. Change to a second airport subscription and confirm no configuration edit is required.

## 16. Publishing and Updates

The first implementation is developed and verified locally. Publication creates the public GitHub repository `jwenwen233/proxy-rules` only after the generated configuration contains no secrets and the user approves publication.

GitHub Actions runs validation on pushes and pull requests. A scheduled workflow checks upstream rule changes daily, generates a reviewable diff, and commits only validated output. Client rule-provider URLs use the public repository's raw files and update every 24 hours.

## 17. Acceptance Criteria

- Both clients can use nodes imported separately from the repository configuration.
- Changing airport subscriptions does not require editing DNS or routing rules.
- Claude and ChatGPT cannot resolve to `DIRECT` under the generated rule order.
- Ordinary DNS uses proxied Cloudflare DoH with no system fallback.
- IPv6 is disabled.
- UDP remains available through capable nodes and never falls back direct when unsupported.
- Rule outputs are generated from one canonical source and validate deterministically.
- No secret or subscription URL is tracked.
- The repository documents installation, updates, DNS interpretation, WebRTC interpretation, and rollback.
