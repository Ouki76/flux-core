# Configuration Reference

flux-core accepts **YAML** (`.yaml`, `.yml`), **JSON** (`.json`) and **JSON with comments** (`.jsonc`). Format is auto-detected by extension, or forced with `--format`.

```bash
flux-core check -c config.yaml    # validate without starting
flux-core run   -c config.yaml    # start the proxy
```

## Top-level structure

| Key | Type | Description |
|---|---|---|
| `include` / `$include` | `string[]` | Files or glob patterns merged into this config (e.g. `outbounds/*.json`) |
| `log` | object | `{ "level": "error\|warn\|info\|debug\|trace" }` |
| `dns` | object | Built-in resolver configuration (see below) |
| `inbounds` | object[] | Listener definitions |
| `outbounds` | object[] \| string[] | Nodes, groups, or proxy-share URIs |
| `route` | object | Routing rules, rule sets, GeoIP |
| `api` | object | Management API (`listen`, `secret`, `allow_insecure_api`) |

Environment variables `${VAR}` and `${VAR:-default}` are expanded everywhere.
An undefined `${VAR}` without a default expands to an empty string — which is why
an empty `api.secret` is treated as *no secret* rather than as an empty password.

## Inbounds

Two forms are supported:

**Shorthand** — `{ "type": "mixed"|"tun"|..., "tag": ..., ... }`

**Layered** — full orthogonal pipeline composition:

```yaml
- tag: socks-in
  carrier:    { type: tcp, listen: 127.0.0.1, listen_port: 10808 }
  security:   { type: tls, ... }            # optional, may be a list (cascade)
  framing:    { type: ws, path: /stream }   # optional, may be a list
  protocol:   { type: socks, username: u, password: p }
  rate_limit:                               # optional DoS hardening
    max_conn_per_ip_per_sec: 10
    burst: 20
    max_concurrent: 10000
```

Carriers: `tcp`, `udp`, `tun`, `redirect`, `tproxy`, `quic` (TUIC/Hysteria 2), WireGuard UDP inbound.
Protocols: `vless`, `trojan`, `vmess`, `shadowsocks`, `socks`, `http`, `tuic`, `hysteria2`, `wireguard`.

## Outbounds

Same layered model, plus groups and URI strings:

```yaml
outbounds:
  - { type: direct, tag: direct }
  - { type: block,  tag: block }

  # Share-link URI (vless://, vmess://, trojan://, ss://, socks5://, http://, hy2://, tuic://)
  # Query params are parsed generically (serde) with Xray/sing-box/Clash aliases
  # (pbk/public_key, sid/short_id, fp/utls, type/transport, ...); unknown keys
  # are preserved, never fatal.
  - "vless://uuid@host:443?security=reality&sni=...&pbk=...&sid=...#my-node"
  - "hy2://password@host:443?obfs=salamander&obfs_password=...&upmbps=200#hy2-node"

  # Layered node: SS-2022 over REALITY + WebSocket
  - tag: ss-stealth
    carrier:  { type: tcp, address: "1.2.3.4:443" }
    security: { type: reality, sni: "www.microsoft.com", public_key: "...", short_id: "..." }
    framing:  { type: ws, path: "/live" }
    protocol: { type: shadowsocks, password: "...", method: "2022-blake3-chacha20-poly1305" }

  # QUIC-native node (hysteria2 / tuic). TLS lives in the QUIC handshake, so the
  # `security` block carries ONLY the TLS parameters — it is not a stream layer.
  #
  # Certificate verification is ON by default. A server with a self-signed
  # certificate therefore needs an explicit `insecure: true` (as in the examples
  # below); omitting `security` entirely no longer disables verification.
  - tag: hy2-node
    carrier:  { type: udp, address: "1.2.3.4:443" }
    security: { type: tls, sni: "cdn.example.com", alpn: ["h3"], insecure: false }
    protocol: { type: hysteria2, password: "...", up_mbps: 200, down_mbps: 500 }
  - tag: tuic-node
    carrier:  { type: udp, address: "1.2.3.4:443" }
    security: { type: tls, sni: "cdn.example.com", insecure: false }
    protocol: { type: tuic, uuid: "...", password: "...", congestion_control: bbr }

  # Groups
  - { type: selector,     tag: pick,  outbounds: [a, b], default: a }
  - { type: urltest,      tag: auto,  outbounds: [a, b], url: "https://www.gstatic.com/generate_204", interval: "5m", tolerance: 50 }
  - { type: fallback,     tag: fb,    outbounds: [a, b] }
  - { type: loadbalance,  tag: lb,    outbounds: [a, b], strategy: round-robin }  # or consistent-hashing
```

Outbound graphs are validated at startup: missing references and dependency cycles are hard errors.

## DNS

```yaml
dns:
  listen: 127.0.0.1:5353          # serve DNS here (optional but needed for fake-IP)
  servers:
    - https://1.1.1.1/dns-query   # DoH (RFC 8484)
    - 8.8.8.8:53                  # plain UDP
  fakeip:
    enabled: true
    inet4_range: 198.18.0.0/15
  client_subnet: "1.2.3.0/24"     # optional EDNS
  rules:                          # per-domain DNS routing
    - domains: ["example.com"]
      servers: ["https://8.8.8.8/dns-query"]
```

**Fake-IP** answers `A` queries from `inet4_range` (TTL 1 s) and answers `AAAA`
with NODATA so clients fall back immediately; the dispatcher maps the synthetic
address back to the name, which is what makes `domain_suffix`/`rule_set` routing
work for applications that resolve names themselves. Point the operating system
or browser at `dns.listen`. Without `fakeip.enabled` the same listener behaves as
a plain forwarding resolver.

## Routing

```yaml
route:
  geoip_path: /etc/flux-core/geoip.mmdb
  final: direct                    # fallback outbound tag
  rule_set:
    - tag: ads
      type: remote                 # local | inline | remote
      path: https://example.org/ads.txt
      update_interval: 24h         # optional hot refresh
      cache_path: /var/cache/flux-core/ads.txt   # optional disk cache
  rules:
    - domain_suffix: ["internal.corp"]
      outbound: direct
    - rule_set: [ads]
      outbound: block
    - ip_cidr: ["10.0.0.0/8"]
      network: [tcp, udp]
      invert: false
      outbound: direct
```

Rule fields: `inbound`, `domain`, `domain_suffix`, `domain_keyword`, `ip_cidr`, `port`, `port_range`, `rule_set`, `geosite`, `geoip`, `process_name`, `network`, `invert`. Every rule requires `outbound`.

Remote rule-set fetch failures never break routing: the last cached/compiled matcher stays active.

Remote rule sets are fetched over HTTP/1.1 with `Content-Length` and
`Transfer-Encoding: chunked` both handled; compressed responses are rejected
rather than silently mis-parsed. The loader logs a **warning** when a fetched
file yields zero usable rules (every `rule_set` rule would then match nothing and
traffic would fall through to `final`) and when lines are skipped.

Rule-set lines may be Clash style (`IP-CIDR,1.2.3.4/32,no-resolve`,
`DOMAIN-SUFFIX,example.com`) or V2Ray/sing-box style (`suffix:example.com`,
`domain:…`, `keyword:…`, `ip-cidr:…`). Trailing Clash modifiers such as
`no-resolve` are accepted; unsupported Clash types (`GEOIP`, `PROCESS-NAME`, …) are
counted and reported, never applied silently.

> **`IP-CIDR` and `no-resolve` — read this before relying on an IP rule.**
> Routing here is decided **without resolving the destination**: the router sees
> `Domain("example.com")` and only a rule on the *name* can match it. An
> `IP-CIDR` rule applies only when the client sent an address literal (a SOCKS5 or
> VLESS request for `1.2.3.4:443`, or a TUN packet, which is always an IP).
> `no-resolve` is therefore trivially honoured, and a rule that *depends* on
> resolution — "block any connection whose IP is in 10.0.0.0/8" applied to a domain
> — silently does not fire. That is a deliberate trade (no DNS lookup per
> connection, no resolver in the matching path), not an oversight; if you need
> IP-based decisions, give the rule a domain counterpart or use a TUN inbound,
> where every destination is already an address.

## API

```yaml
api:
  listen: 127.0.0.1:9090        # or unix:///run/flux-core/api.sock
  secret: ${FLUX_API_SECRET}    # required for non-loopback listeners
```

See [api.md](api.md) for endpoints and [security.md](security.md) for hardening requirements.

## Examples

Complete annotated examples live in [`examples/`](../examples/) (`config.yaml`, `config.jsonc`, `nodes.json`).
