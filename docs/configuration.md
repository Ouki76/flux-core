# Configuration Reference

flux-core accepts **YAML** (`.yaml`, `.yml`), **JSON** (`.json`) and **JSON with comments** (`.jsonc`). Format is auto-detected by extension (and by content when the extension says nothing), or forced with `--format`.

```bash
flux-core check -c config.yaml    # validate without starting
flux-core trace -c config.yaml -d example.com:443 -n tcp   # dry-run the router
flux-core run   -c config.yaml    # start the proxy
```

`--format` accepts `auto` (default), `json` (also used for `.jsonc`) and `yaml`.

## Strictness

Validation happens at load time and is meant to fail loudly:

- **Duplicate tags** (inbound or outbound) are an error.
- **Dangling references** — a rule, `final`, or group candidate naming an unknown outbound — are an error, as are **cycles between groups**.
- A group with an **empty candidate list** is an error; a selector `default` that is not one of its candidates is an error.
- A `rule_set` whose local `path` cannot be read is a startup error.
- UUIDs (VLESS/VMess/TUIC), REALITY public keys, WireGuard keys and CIDRs are validated before any listener binds.
- Unknown fields are rejected at the **top level** and inside `log`, `dns`, `dns.fakeip` and `api`. Inside `inbounds`, `outbounds`, `route` and individual rules, unknown keys are currently **ignored** — a typo there is silent, so check the spelling against this page.

## Environment variables

`${VAR}` and `${VAR:-default}` are expanded in both JSON and YAML files. `$$` unescapes to a literal `$`.

- An undefined `${VAR}` **without** a default is a **configuration error** (the load aborts with the variable name). It is *not* expanded to an empty string — that used to turn a typo into a working-looking config with an empty secret or password.
- In YAML, lines whose first non-space character is `#` are left untouched, so a commented-out `# secret: ${DB_PASS}` cannot abort the load. In JSON/JSONC, comments are stripped before expansion for the same reason.
- Nested defaults (`${A:-${B}}`) are rejected.

An empty `api.secret` (for example `${FLUX_API_SECRET:-}`) is treated as *no secret* by the API server.

## Includes

`include` (alias `$include`) takes file names or glob patterns; relative paths are resolved against the directory of the file that lists them.

```yaml
include: ["outbounds/*.json", "rules/ads.yaml"]
```

- Inbounds, outbounds, `route.rules`, `route.rule_set` and `dns.servers` are **appended**.
- `log`, `api`, `route.final`, `dns.fakeip` are taken from the **first** file that sets them.
- `dns.rules`, `dns.client_subnet` and `dns.listen` are **not** merged: when both
  the root and an included file define `dns`, the included file's `rules` are
  silently dropped. Define DNS rules in the root file until this is fixed.
- A literal path that does not exist is an error; a glob that matches nothing is an error.
- Cycles are detected (a file is loaded once) and include chains deeper than 32 files are refused.

## Top-level structure

| Key | Type | Default | Description |
|---|---|---|---|
| `include` / `$include` | `string[]` | `[]` | Files or glob patterns merged into this config |
| `flux` | `string` | — | Accepted and **ignored**; no behaviour depends on it |
| `log` | object | — | `{ "level": "error\|warn\|info\|debug\|trace" }` |
| `dns` | object | — | Built-in resolver (see below) |
| `inbounds` | object[] | `[]` | Listener definitions |
| `outbounds` | object[] \| `string[]` | `[]` | Nodes, groups, or proxy-share URIs |
| `route` | object | — | Routing rules, rule sets, GeoIP |
| `api` | object | — | Management API |

`log.level` defaults to `info`; `RUST_LOG` overrides it. An unrecognised level falls back to `info`.

## API

```yaml
api:
  listen: 127.0.0.1:9090        # or unix:///run/flux-core/api.sock
  secret: ${FLUX_API_SECRET:-}  # required for a public bind; empty = no secret
  allow_insecure_api: false     # opt out of the guard below
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `listen` | string | — | **Required for the API to start.** `host:port`, `unix:///path.sock`, or any path ending in `.sock` |
| `secret` | string | unset | Bearer token. Empty/whitespace-only is treated as unset |
| `allow_insecure_api` | bool | `false` | Allow a bind to `0.0.0.0`/`::` without a secret |

A bind to the unspecified address (`0.0.0.0`, `::`) without a `secret` is **refused** at startup unless `allow_insecure_api: true`. A bind to a *specific* non-loopback address without a secret is allowed and logs a warning — put a reverse proxy with TLS in front of it, or use a unix socket.

See [api.md](api.md) for endpoints and [security.md](security.md) for hardening requirements.

## DNS

```yaml
dns:
  listen: 127.0.0.1:5353          # serve DNS here
  servers:
    - https://1.1.1.1/dns-query   # DoH
    - tls://1.1.1.1:853           # DoT
    - 8.8.8.8:53                  # plain UDP
  fakeip:
    enabled: true
    inet4_range: 198.18.0.0/15    # default
    inet6_range: fc00::/18        # default
  client_subnet: "1.2.3.0/24"     # global EDNS Client Subnet
  rules:                          # per-domain DNS routing
    - domains: ["example.com"]
      servers: ["https://8.8.8.8/dns-query"]
      client_subnet: "4.4.4.0/24"
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `listen` | string | unset | Starts a DNS inbound. Without it, nothing serves DNS |
| `servers` | `string[]` | `[]` | `http(s)://` DoH, `tls://`/`dot://` DoT, `quic://`/`doq://` DoQ, or `ip[:port]` UDP (port 53). Invalid addresses are an error, never a silent fallback |
| `fakeip.enabled` | bool | `false` | Hand out synthetic addresses |
| `fakeip.inet4_range` | string | `198.18.0.0/15` | IPv4 pool |
| `fakeip.inet6_range` | string | `fc00::/18` | IPv6 pool. Set to `off`, `none`, `disabled` or `""` to answer `AAAA` with **NODATA** instead |
| `client_subnet` | string | unset | Global EDNS Client Subnet (CIDR) |
| `rules[].domains` | `string[]` | `[]` | Suffixes routed to this rule's servers |
| `rules[].servers` | `string[]` | `[]` | Upstreams for those domains |
| `rules[].client_subnet` | string | unset | Per-rule ECS override |

**Fake-IP** answers `A` from `inet4_range` and `AAAA` from `inet6_range` (both TTL 1 s), so clients do not wait for IPv6 to time out. Both pools are **on by default**; with `inet6_range: off` (or an empty value) `AAAA` is answered with NODATA so clients fall back to IPv4 immediately. The dispatcher maps a synthetic address back to the name, which is what makes `domain_suffix`/`rule_set` routing work for applications that resolve names themselves. Point the operating system or browser at `dns.listen`.

Without `fakeip.enabled` the same listener behaves as a plain forwarding resolver. Resolution is deadline-bounded end to end (12 s) with a 4 s budget per transport step.

## Inbounds

Two forms are supported and may be mixed in one file.

**Shorthand / system inbounds** — `{ "type": "tun"|"mixed"|"redirect"|"tproxy"|"wireguard", "tag": ..., ... }`:

```yaml
inbounds:
  - { type: tun,    tag: tun0, interface_name: tun0, mtu: 9000 }
  - { type: mixed,  tag: mixed-in, listen: 127.0.0.1, listen_port: 7890 }
```

| Type | Field | Type | Default | Notes |
|---|---|---|---|---|
| `tun` | `tag` | string | — | Required |
| | `interface_name` | string | `tun0` | Device to open |
| | `mtu` | int | **`9000`** | Programmed into the device with `SIOCSIFMTU`; clamped to 576–65535 |
| `mixed` | `tag`, `listen`, `listen_port` | string / string / int | — | Required; auto-detects SOCKS5 vs HTTP |
| | `users[]` | `{username, password}[]` | `[]` | Empty = no authentication |
| | `rate_limit` | object | unset | See *Rate limiting* |
| `redirect` | `tag`, `listen`, `listen_port` | — | — | Required; `SO_ORIGINAL_DST` |
| `tproxy` | `tag`, `listen`, `listen_port` | — | — | Required; `IP_TRANSPARENT` |
| `wireguard` | `tag`, `listen`, `listen_port` | — | — | Required; WireGuard/AmneziaWG server |
| | `private_key` | string | — | Required; 64 hex chars or 32-byte Base64 |
| | `peers[]` | object[] | — | Required, at least one |
| | `peers[].public_key` | string | — | Required |
| | `peers[].preshared_key` | string | unset | Optional PSK |
| | `peers[].allowed_ips` | `string[]` | `[]` | CIDRs allowed as inner source; empty = any |
| | `mtu` | int | `1420` | Inner tunnel MTU |
| | `awg` | object | unset | AmneziaWG parameters — **all nine fields are required**: `jc`, `jmin`, `jmax`, `s1`, `s2`, `h1`, `h2`, `h3`, `h4` |

`tun.mtu` is applied to the interface when the inbound starts. It is not cosmetic: the kernel segments by the *device* MTU, and the datapath is syscall-bound (one packet per `read`/`write`), so the jumbo default is the single biggest throughput knob on TUN. Set `mtu: 1500` when the device has to match a 1500-byte path.

**Layered** — full orthogonal pipeline composition:

```yaml
- tag: socks-in
  carrier:    { type: tcp, listen: 127.0.0.1, listen_port: 10808 }
  security:   { type: tls }    # add certificate_path/key_path to use a real certificate
  framing:    { type: ws, path: /stream }
  protocol:   { type: socks, username: u, password: p }
  rate_limit:
    max_conn_per_ip_per_sec: 10
    burst: 20
    max_concurrent: 10000
```

`carrier.type` is **`tcp` or `udp` only**. TUN/REDIRECT/TPROXY are inbound *types* (above), not carriers; QUIC protocols use a `udp` carrier and carry their own TLS.

| Carrier field (`tcp`/`udp`) | Type | Default | Notes |
|---|---|---|---|
| `listen` | string | `0.0.0.0` | Address to bind |
| `listen_port` | int | `0` | **Set this explicitly** — `0` asks the kernel for an ephemeral port |
| `address` | string | unset | `ip:port`; overrides `listen`/`listen_port` |

Inbound `security` (may be a single object or a list, applied in order):

| Type | Field | Default | Notes |
|---|---|---|---|
| `tls` | `certificate_path`, `key_path` | unset | Both or neither. Without them a self-signed `localhost` certificate is generated at startup |
| | `server_name` | unset | Accepted but currently **not used** by the TLS acceptor |
| `reality` | `server_names` | — | Required list; an empty list accepts any SNI |
| | `private_key` | — | Required, 32 bytes |
| | `short_ids` | — | Required, may be empty |
| | `fallback` | unset | Plain TCP target for non-REALITY clients |
| `shadowtls` | `version` | `3` | **Only v3 exists.** Any other value is refused at load time |
| | `password`, `fallback` | — | Required |
| | `server_names` | `[]` | Accepted cover SNIs; empty disables the check |

Inbound `framing` (single object or list): `ws` / `websocket`, `httpupgrade` / `upgrade`, `h2` / `http2`, `grpc` / `gun`. Only `ws` and `httpupgrade` take a `path`; **omitting it accepts any request path**.

Inbound `protocol` is the same object described under [Outbounds → Protocol](#protocol), with two differences: a UDP carrier supports only `shadowsocks`, `hysteria2` and `tuic`, and for those the `security`/`framing` blocks are ignored (QUIC performs its own TLS with a generated self-signed certificate). Hysteria 2's `up_mbps`, `down_mbps`, `hop_interval_secs` and `h3` only affect the outbound.

### Rate limiting

Optional per-inbound DoS hardening. Rejections happen before per-connection allocation.

| Field | Type | Default | Notes |
|---|---|---|---|
| `max_conn_per_ip_per_sec` | int | `0` | New connections/second per client IP; 0 = unlimited |
| `burst` | int | `max(rate, 1) × 2` | Token-bucket burst |
| `max_concurrent` | int | `0` | Global concurrent cap; 0 = unlimited |

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
  - "vless://a1b2c3d4-e5f6-7890-1234-56789abcdef0@host:443?security=reality&sni=example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=&sid=ab12#my-node"
  - "hy2://pw@host:443?obfs=salamander&obfs_password=pw&upmbps=200#hy2-uri"

  # Layered node: SS-2022 over REALITY + WebSocket
  - tag: ss-stealth
    carrier:  { type: tcp, address: "1.2.3.4:443" }
    security: { type: reality, sni: "www.microsoft.com", public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", short_id: "ab12" }
    framing:  { type: ws, path: "/live" }
    protocol: { type: shadowsocks, password: "pw", method: "2022-blake3-chacha20-poly1305" }

  # QUIC-native node (hysteria2 / tuic). TLS lives in the QUIC handshake, so the
  # `security` block carries ONLY the TLS parameters — it is not a stream layer.
  #
  # Certificate verification is ON by default. A server with a self-signed
  # certificate therefore needs an explicit `insecure: true`; omitting `security`
  # entirely no longer disables verification.
  #
  # A node behind a private CA should pin that CA instead — ca_cert_path takes one
  # or more PEM files whose certificates are appended to the built-in roots, which
  # is strictly better than turning verification off:
  #   security: { type: tls, sni: "node.internal", ca_cert_path: ["/etc/flux/ca.pem"] }
  - tag: hy2-node
    carrier:  { type: udp, address: "1.2.3.4:443" }
    security: { type: tls, sni: "cdn.example.com", alpn: ["h3"], insecure: false }
    protocol: { type: hysteria2, password: "pw", up_mbps: 200, down_mbps: 500 }
  - tag: tuic-node
    carrier:  { type: udp, address: "1.2.3.4:443" }
    security: { type: tls, sni: "cdn.example.com", insecure: false }
    protocol: { type: tuic, uuid: "a1b2c3d4-e5f6-7890-1234-56789abcdef0", password: "pw", congestion_control: bbr }

  # Groups
  - { type: selector,     tag: pick,  outbounds: [ss-stealth, hy2-node], default: ss-stealth }
  - { type: urltest,      tag: auto,  outbounds: [ss-stealth, hy2-node], url: "https://www.gstatic.com/generate_204", interval: "5m", tolerance: 50 }
  - { type: fallback,     tag: fb,    outbounds: [ss-stealth, hy2-node] }
  - { type: loadbalance,  tag: lb,    outbounds: [ss-stealth, hy2-node], strategy: round-robin }  # or consistent-hashing
```

### Carrier (`tcp` / `udp`)

| Field | Type | Notes |
|---|---|---|
| `address` | string | `host:port`; takes precedence |
| `server` + `port` | string + int | Used when `address` is absent. At least one form is required |

### Security

A single object, or a list applied in order.

| Type | Field | Default | Notes |
|---|---|---|---|
| `tls` | `sni` | carrier host | Sent as SNI |
| | `alpn` | `[]` | e.g. `["h3"]` for QUIC |
| | `insecure` | `false` | Skips certificate verification — deliberate opt-in |
| | `utls` | unset | ClientHello fingerprint name |
| `reality` | `public_key` | — | Required, 32 bytes (64 hex or Base64) |
| | `sni` | carrier host | Cover host name |
| | `short_id` | unset | Hex |
| `shadowtls` | `version` | `3` | **Only v3.** Any other value is refused at load time rather than served as v3 |
| | `password`, `sni` | — | Required |
| `fragment` | `length_min` / `length_max` | `1` / `3` | TLS-record fragmentation sizes |
| | `interval_ms` | `10` | Delay between fragments |

`fragment` is a **security** layer, not a framing layer: put it under `security`, not `framing`.

For `hysteria2`/`tuic`, only the first `tls` entry is read (`sni`, `alpn`, `insecure`).

### Framing

| Type | Field | Default | Notes |
|---|---|---|---|
| `ws` / `websocket` | `path` | `/` | Request path |
| | `headers` | `{}` | Extra HTTP headers |
| `httpupgrade` / `upgrade` | `path` | `/` | |
| | `headers` | `{}` | |
| `h2` / `http2` | `path` | `/` | |
| | `headers` | `{}` | |
| `grpc` / `gun` | `service_name` | `GunService` | |
| | `headers` | `{}` | |

### Protocol

| Type | Field | Default | Notes |
|---|---|---|---|
| `vless` | `uuid` | — | Required UUID |
| | `flow` | unset | `xtls-rprx-vision` needs TLS on the carrier |
| `vmess` | `uuid` | — | Required UUID |
| | `security` | unset | e.g. `aes-128-gcm`, `chacha20-poly1305` |
| `trojan` | `password` | — | Required |
| `shadowsocks` / `ss` | `password` | — | Required |
| | `method` | `chacha20-ietf-poly1305` | `aes-128-gcm`, `aes-256-gcm`, `2022-blake3-aes-128-gcm`, `2022-blake3-aes-256-gcm`, `2022-blake3-chacha20-poly1305`. An unrecognised name currently falls back to the default, so a typo is silent |
| `socks` / `socks5` | `username`, `password` | unset | Both or neither |
| `http` | `username`, `password` | unset | Basic auth |
| `wireguard` / `awg` | `private_key`, `peer_public_key` | — | Required, 32 bytes |
| | `preshared_key` | unset | |
| | `local_address` | `10.0.0.2` / `fd00::2` | Source address inside the tunnel |
| | `keepalive_secs` | `25` | Persistent keepalive; `0` disables |
| | `awg` | unset | All nine AWG fields required |
| `hysteria2` / `hy2` | `password` | — | Required |
| | `up_mbps` | `100` | Brutal pacer send rate |
| | `down_mbps` | `100` | Accepted; not applied (only the send rate is paced) |
| | `hop_interval_secs` | `30` | Port-hopping interval. The native config supplies only the carrier port, so hopping is currently inert; a share-link `ports=` list is parsed but not applied |
| | `h3` | `false` | Accepted for compatibility; the client always authenticates over HTTP/3, so this currently has no effect |
| | `obfs` | unset | Only `salamander` |
| | `obfs_password` | unset | Required when `obfs: salamander` |
| `tuic` / `tuic5` | `uuid`, `password` | — | Required |
| | `congestion_control` | `bbr` | Accepted for compatibility; currently **not applied** — the QUIC stack uses its built-in controller |
| | `zero_rtt` | `true` | Accepted for compatibility; currently **not applied** |

### Groups

| Type | Fields | Defaults | Notes |
|---|---|---|---|
| `direct` | `tag`, `tls_fragment` | `tls_fragment` unset | `tls_fragment` is a fragmentation config (`enabled`, `length_min`, `length_max`, `interval_ms`) |
| `block` | `tag` | — | Rejects the connection |
| `selector` | `outbounds`, `default` | `default` = first | `default` must be one of `outbounds` |
| `urltest` | `outbounds`, `url`, `interval`, `tolerance` | `http://cp.cloudflare.com/generate_204`, `300s`, `50` ms | Tolerance is in milliseconds |
| `fallback` | `outbounds`, `url`, `interval` | `interval` `300s` | First healthy candidate wins |
| `loadbalance` | `outbounds`, `strategy` | `round-robin` | Or `consistent-hashing` |

`interval` accepts `30s`, `5m`, `1h`, or a bare number of seconds.

### Multiplexing

Optional per node (`multiplex:`), **off by default**. Enabling it changes the wire format, so both peers must agree.

| Field | Type | Default | Notes |
|---|---|---|---|
| `enabled` | bool | `false` | |
| `protocol` | string | `smux` | Only `smux` exists; anything else is a config error |
| `max_streams` | int | `128` | Streams per physical connection |
| `padding` | bool | `false` | Client pads; inbound requires padding |
| `max_connections` | int | `4` | Physical sessions kept open |
| `keepalive_secs` | int | `30` | `0` disables |
| `idle_timeout_secs` | int | `300` | `0` disables |

Multiplexing is only supported for `vless`, `vmess`, `trojan` and `shadowsocks`, and on inbounds only with a **`tcp`** carrier. Any other combination is refused at load time.

## Routing

```yaml
route:
  # geoip_path: /etc/flux-core/geoip.mmdb   # optional; the file must exist if set
  final: direct                    # fallback outbound tag (default: direct)
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

### Rule sets

| Field | Type | Default | Notes |
|---|---|---|---|
| `tag` | string | — | Referenced by `rule_set`/`geosite` |
| `type` | string | inferred | `local`, `inline` or `remote`; any other value is an error. An `http(s)://` `path` implies `remote` |
| `path` | string | unset | File for `local`/`inline`, URL for `remote` |
| `update_interval` | string | unset | Remote only. Without it the fetch happens once |
| `cache_path` | string | `$XDG_CACHE_HOME/flux-core/rulesets/<tag>-<hash>.txt` | Remote only; the last good body is applied at startup |
| `ip_cidr`, `domain`, `domain_suffix`, `domain_keyword` | `string[]` | `[]` | Inline entries, merged with anything loaded/fetched |

Rule-set lines may be Clash style (`IP-CIDR,1.2.3.4/32,no-resolve`, `DOMAIN-SUFFIX,example.com`) or V2Ray/sing-box style (`suffix:example.com`, `full:example.com`, `domain:example.com`, `keyword:…`, `ip-cidr:…`). Trailing Clash modifiers such as `no-resolve` are accepted; unsupported Clash types (`GEOIP`, `PROCESS-NAME`, …) are counted and reported, never applied silently.

**Remote rule sets** are fetched over HTTP/1.1 only:

- `Content-Length` and `Transfer-Encoding: chunked` are both handled; with neither, the body is read until EOF (or the 16 MiB cap).
- Compressed responses are **rejected** (only identity encoding), rather than silently mis-parsed.
- Redirects are followed (max 3); the body is capped at 16 MiB and the whole fetch at 30 s.
- A rule set starts **empty** — it matches nothing until the first fetch succeeds. The startup cache, when present, is applied before any network round trip.
- A refresh that yields **zero usable rules keeps the previous contents**. The loader logs a **warning** when a fetched file yields zero usable rules (every `rule_set` rule would then match nothing and traffic would fall through to `final`) and when lines are skipped.
- Fetch failures never break routing: the last good matcher stays active.

### Rules

Every rule requires `outbound`. Criteria inside one rule are **ANDed**; multiple values inside one criterion are **ORed**. The **first matching rule in file order wins**, otherwise `route.final` applies.

| Field | Type | Notes |
|---|---|---|
| `inbound` | `string[]` | Inbound tags |
| `domain` | `string[]` | Exact names |
| `domain_suffix` | `string[]` | Suffix match |
| `domain_keyword` | `string[]` | Substring match |
| `ip_cidr` | `string[]` | CIDR or bare IP |
| `port` | int or `int[]` | Destination port(s) |
| `port_range` | `string[]` | `1000-2000` or `1000:2000` |
| `rule_set` | `string[]` | Rule-set tags |
| `geosite` | `string[]` | Rule-set tags too; a name that does not exist simply never matches |
| `geoip` | `string[]` | Country codes from `geoip_path`; `private` expands to the private/loopback/link-local ranges |
| `process_name` | `string[]` | Executable name (`comm`), case-insensitive. Needs a resolvable source process; otherwise the rule does not match |
| `network` | `string[]` | `tcp` / `udp` |
| `invert` | bool | Inverts the whole rule |
| `outbound` | string | Required |

`geoip_path` points at a MaxMind-format database; if it is set but cannot be loaded, startup fails. GeoIP matching needs an **IP destination**, so it behaves like `ip_cidr` below with respect to domains.

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
> where every destination is already an address. Fake-IP works too: the DNS
> listener hands out an address inside `fakeip.inet4_range` and the dispatcher
> maps it back to the name, so a `domain`/`rule_set` rule still matches.

## Examples

Complete annotated examples live in [`examples/`](../examples/) (`config.yaml`, `config.jsonc`, `nodes.json`).