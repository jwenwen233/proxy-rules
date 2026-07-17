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
│       ├── reject-domain.yaml
│       ├── ai.yaml
│       ├── openai-voice-ip.yaml
│       ├── media.yaml
│       ├── messaging.yaml
│       ├── apple-microsoft.yaml
│       ├── cn-domain.yaml
│       └── cn-ip.yaml
├── configs/
│   ├── shadowrocket.conf
│   └── clash-verge-script.js
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
  - type: process-name
    value: ToDesk
    targets: [mihomo]
```

Supported canonical types are `domain`, `domain-suffix`, `domain-keyword`, `ip-cidr`, `ip-asn`, and `process-name`. Records apply to both clients unless an explicit `targets` list limits them. This is required because Mihomo supports process-name routing while iOS Shadowrocket does not provide equivalent process matching. Generation converts each record only for compatible targets and fails rather than silently dropping an unsupported shared record.

Broad `domain-keyword` entries are disallowed by default because they commonly route unrelated sites. A keyword requires an explicit allow entry in the validator configuration and a comment explaining the scope.

## 6. Upstream Sources and Licensing

The repository is licensed GPL-3.0 and preserves source attribution in the README and lock file.

- MetaCubeX `meta-rules-dat` supplies maintained CN, advertising, media, messaging, Apple, and Microsoft datasets.
- Anthropic's official Claude Code enterprise network documentation is authoritative for Claude and Claude Code destinations.
- OpenAI's official ChatGPT network recommendations are authoritative for ChatGPT, OpenAI, WebSocket, file, app, and voice destinations.
- Net.Coffee's Claude list is supplemental. Entries are accepted only when they do not create an unsafe broad match and are not contradicted by official documentation.

`sync_upstreams.py` records the upstream URL, retrieval timestamp, and content SHA-256 in `source/upstream.lock.json`. Generated output is reproducible from the locked inputs.

## 7. Policy Groups

Both clients expose equivalent logical groups. Stable internal names use a `PRX-` prefix to minimize collisions with airport node names. The README explains each ASCII group name; rule references and displayed group names stay identical.

- `PRX-Manual`: all usable imported nodes, excluding quota, expiry, website, and informational entries.
- `PRX-Auto`: URL-test over all usable imported nodes.
- `PRX-AI`: select between `PRX-Manual` and `PRX-Auto`; no `DIRECT` option.
- `PRX-Media`: select between `PRX-Manual` and `PRX-Auto`.
- `PRX-Messaging`: select between `PRX-Manual` and `PRX-Auto`.
- `PRX-Apple-Microsoft`: select between `DIRECT`, `PRX-Manual`, and `PRX-Auto`; default is `DIRECT`.
- `PRX-Proxy`: select between `PRX-Manual` and `PRX-Auto`; this is the final overseas policy.

For Mihomo, `PRX-Manual` and `PRX-Auto` use `include-all: true` plus exclusion filters. This includes both inline proxies and proxy providers without including other proxy groups. The enhancement script rejects an airport profile containing a proxy, group, or rule provider with a reserved `PRX-*` name instead of producing an ambiguous configuration. It preserves non-reserved airport groups because chained nodes may refer to them, while the new routing rules reference only the repository's groups.

For Shadowrocket, dynamic `policy-regex-filter` groups draw from nodes already imported on the home page. A user imports or changes subscriptions independently, then applies the rules configuration. The device acceptance test must verify this behavior against the installed Shadowrocket version and two separate subscriptions; if a future app version changes this behavior, the documented fallback is to enable the subscription selector for each group in the UI without editing routing or DNS rules.

## 8. Rule Precedence

Rules are evaluated in this fixed order:

1. Loopback, LAN, private ranges, captive portal, and essential system connectivity: `DIRECT`.
2. ToDesk processes/domains and `scnet.cn`: `DIRECT`.
3. Advertising, tracking, hijacking, and known malicious destinations: `REJECT`.
4. Claude, Anthropic, ChatGPT, OpenAI, and their required exact infrastructure destinations: `PRX-AI`.
5. Telegram and Discord: `PRX-Messaging`.
6. Streaming services: `PRX-Media`.
7. Apple and Microsoft: `PRX-Apple-Microsoft`.
8. China domains and China IP ranges: `DIRECT`.
9. Everything else: `PRX-Proxy`.

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

Shared infrastructure such as all of `sentry.io`, all Datadog domains, all Intercom domains, `storage.googleapis.com`, and `raw.githubusercontent.com` is not assigned to AI by a broad keyword. It is still proxied by the final `PRX-Proxy` policy. Exact endpoints may be assigned to AI when official documentation identifies them.

### OpenAI and ChatGPT

The AI set includes official OpenAI families and exact dependencies, including:

- `openai.com`
- `chatgpt.com`
- `auth.openai.com`
- `oaistatic.com`
- `oaiusercontent.com`
- `oaistatsig.com`
- Official authentication, WorkOS, app, WebSocket, upload, and exact telemetry endpoints

ChatGPT Voice IP ranges are synchronized from OpenAI's maintained `chatgpt-voice.json` and routed to `PRX-AI`. The dedicated OpenAI ranges are routed as a whole instead of trying to combine an external IP-only rule provider with a port-3478 condition, because that compound form is not represented consistently by both clients. If the voice list cannot update, the previous validated list remains in `dist`; the build does not replace it with an empty file.

## 10. DNS and Leak Prevention

### Shadowrocket

- `dns-server = https://1.1.1.1/dns-query#proxy`.
- `fallback-dns-server = https://1.0.0.1/dns-query#proxy`; it remains inside the proxy path and never names `system`.
- `dns-direct-system = false`.
- `ipv6 = false` and `prefer-ipv6 = false`.
- `use-local-host-item-for-proxy = false`, preventing a local hosts entry from replacing a proxied hostname.
- `hijack-dns = 8.8.8.8:53,8.8.4.4:53` captures common hard-coded plain-DNS destinations.
- `proxy-dns-server = https://1.1.1.1/dns-query` resolves node hostnames by direct encrypted bootstrap without using system DNS. It is intentionally not marked `#proxy`, because the node hostname must be resolved before the proxy tunnel can exist.
- `udp-policy-not-supported-behaviour = REJECT`, preventing silent direct fallback while retaining UDP for capable nodes.

`dns-fallback-system` is not emitted because it is not a documented Shadowrocket key. Preventing system fallback is achieved by explicitly configuring `fallback-dns-server` to a proxied DoH endpoint and never setting it to `system` or an empty value.

### Clash Verge Rev/Mihomo

The global enhancement script overrides DNS and relevant TUN fields while preserving application-controlled ports and service settings:

- DNS enabled, IPv6 disabled, `fake-ip` enhanced mode.
- `use-hosts: false` and `use-system-hosts: false`.
- `respect-rules: true`, together with the required `proxy-server-nameserver`.
- TUN DNS hijack includes `any:53`.
- The sole ordinary resolver is the quoted YAML scalar `'https://1.1.1.1/dns-query#PRX-Proxy'`, explicitly routed through the repository's main proxy group. Quoting is mandatory because an unquoted `#` begins a YAML comment.
- No `fallback` resolver is configured. Mihomo enables geo-filtered fallback behavior when that field exists, which would create unnecessary parallel or conditional queries for this strict single-path design.
- No system nameserver is configured.
- Both `default-nameserver` and `proxy-server-nameserver` use the quoted, explicitly direct, encrypted IP-addressed DoH scalar `'https://1.1.1.1/dns-query#DIRECT'`, avoiding a circular dependency before a proxy connection exists. The explicit `#DIRECT` is required because `respect-rules: true` otherwise allows the bootstrap resolver's own connection to follow the final proxy rule. These resolvers are only bootstrap paths for DoH server and node hostnames, not ordinary website queries.
- Fake-IP exclusions are limited to LAN discovery, captive portal, and service-discovery names that require real addresses. Fake-IP filtering is not presented as a WebRTC/STUN leak control.

Bootstrap DNS is a necessary exception for airport nodes whose server is specified by hostname: the proxy hostname must be resolved before a proxy tunnel exists. This bootstrap is encrypted and restricted to proxy-server hostnames. Ordinary website DNS continues through the proxy.

The merge script does not force-enable TUN; the user controls the TUN switch in Clash Verge. When TUN is enabled, the DNS hijack prevents applications from bypassing Mihomo with hard-coded port-53 resolvers.

## 11. UDP and WebRTC

UDP-capable nodes receive UDP traffic through the same selected policy. The configuration does not reject WebRTC, ChatGPT Voice, conferencing, games, or QUIC.

If a provider intentionally uses different TCP and UDP NAT pools, WebRTC tests can report two proxy egress IPs. This is not a local-IP bypass and cannot be corrected by client routing rules. The README explains how to distinguish provider-side split egress from a real local ISP leak.

## 12. Failure Handling

- Rule providers update every 24 hours and retain the last valid cache.
- Mihomo rule providers set `proxy: PRX-Proxy`, so remote rule downloads use the proxy after the embedded critical rules and groups are available.
- Mihomo provider behavior matches the generated content: `domain` for domain-only sets, `ipcidr` for IP-only sets, and `classical` only for mixed rule types.
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
- Claude and ChatGPT representative domains map to `PRX-AI`.
- CN and private destinations map to `DIRECT`.
- Advertising samples map to `REJECT`.
- Unknown overseas domains reach final `PRX-Proxy`.
- IPv6 and system-DNS fallback remain disabled.
- No secrets exist in tracked files.
- A fixture airport profile is enhanced without losing its proxies or proxy providers.
- The Clash enhancement replaces, rather than prepends to, the airport's `rules`; this prevents an airport's earlier rules from shadowing the personal rules. It merges namespaced `PRX-*` rule providers and groups while preserving non-reserved airport `rule-providers`, `proxy-groups`, `proxies`, `proxy-providers`, ports, and unrelated runtime fields.
- Inline proxies and proxy providers both populate `PRX-Manual` and `PRX-Auto` through `include-all: true`.
- Mihomo validates a composed fixture configuration with its configuration-test command.

Shadowrocket has no supported desktop CLI validator, so its tests parse sections, validate supported rule syntax, validate policy references, and compare generated records against golden fixtures. Final device verification is documented as a manual acceptance test.

## 15. Manual Acceptance Test

For each client:

1. Import a test airport subscription separately.
2. Apply the generated configuration/enhancement.
3. Confirm policy groups contain imported nodes.
4. Confirm Claude and ChatGPT use `PRX-AI`.
5. Confirm a representative CN site is direct and an unknown overseas site is proxied.
6. Confirm ad samples are rejected.
7. Confirm public HTTP egress matches the selected proxy.
8. Run DNS leak detection and verify no mobile/broadband ISP resolver appears.
9. Run WebRTC detection and distinguish local-IP leakage from provider-side UDP split egress.
10. Change to a second airport subscription and confirm no configuration edit is required.

## 16. Publishing and Updates

The first implementation is developed and verified locally. Publication creates the public GitHub repository `jwenwen233/proxy-rules` only after the generated configuration contains no secrets and the user approves publication.

GitHub Actions runs validation on pushes and pull requests. A scheduled workflow checks upstream rule changes daily, generates a reviewable diff, and opens or updates a pull request after validation; it never pushes unattended changes directly to the default branch. Client rule-provider URLs use concrete `raw.githubusercontent.com/jwenwen233/proxy-rules/...` paths and update every 24 hours.

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
