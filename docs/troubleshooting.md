# Troubleshooting

## Startup failures

| Symptom | Likely cause | Fix |
|---|---|---|
| `insecure API listening on 0.0.0.0 ... rejected` | API bound to a public address without `secret` | Set `api.secret` or bind to `127.0.0.1`; last resort `allow_insecure_api: true` |
| `invalid API listen address` | Malformed `api.listen` | Use `host:port` or `unix:///path.sock` |
| Config validation errors | Bad outbound reference or cycle | Run `flux-core check -c config.yaml`; error names the offending tag |
| `Permission denied` on TUN/TPROXY/REDIRECT | Missing capabilities | Grant `CAP_NET_ADMIN` / `CAP_NET_BIND_SERVICE` (see deployment.md) |
| REALITY outbound fails handshake | Wrong `public_key`/`short_id`/SNI mismatch | Re-derive the public key from the server's private key; verify `sni` matches the decoy |

## Runtime issues

**Connections dropped at high rate on a public inbound** — check `rate_limit` counters; clients over the per-IP budget are rejected before allocation. Raise `burst` or `max_conn_per_ip_per_sec` if legitimate.

**UDP replies missing** — was a past bug class (fixed: reply-destination normalization, `select!` arm drops). If seen on an old build, upgrade; on current builds capture `RUST_LOG=flux_protocol=debug,flux_outbound=debug`.

**TUN stalls under reordering** — fixed in RFC 793 OOO reassembly with u32 wraparound handling. Upgrade if on an older build.

**Remote rule set not updating** — fetch failures are silent-by-design (routing must not break). Check logs at `warn` level; verify the URL returns the expected format and is within the size cap; delete the disk cache file to force a clean fetch.

**DNS leaks / slow resolution** — verify `dns.servers` ordering, per-domain `dns.rules`, and that DoH endpoints are reachable; use `POST /api/v1/dns/resolve` to test the built-in resolver directly.

**Memory growth** — run `scripts/soak.sh` and compare against the RSS assertions; report with the soak log. The per-connection buffer pool is bounded; unbounded growth is a bug.

## Diagnostics

```bash
# Verbose logs
log: { level: debug }          # or trace for parser-level detail

# Active connections snapshot
curl -s http://127.0.0.1:9090/api/v1/connections | jq

# Router dry-run
curl -s -X POST http://127.0.0.1:9090/api/v1/route/test \
  -H 'Content-Type: application/json' \
  -d '{"destination":"example.com:443","network":"tcp"}'
```
