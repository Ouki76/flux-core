# Management API Reference

Enabled via `api.listen` in the config. Plain HTTP/1.1 over TCP or a unix socket (`unix:///path.sock`).

## Authentication

When `secret` is configured, authenticate with either:

- `Authorization: Bearer <secret>` header (preferred), or
- `?token=<secret>` query parameter (rejected from cross-origin browser contexts).

Requests with an external `Origin` header and no `Authorization` are rejected with `403` before any dispatch (CSRF protection).

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/v1/version` | Binary version |
| GET | `/api/v1/status` | Uptime, counts, health snapshot |
| GET | `/api/v1/metrics` | Prometheus text format (`text/plain; version=0.0.4`) |
| GET | `/api/v1/traffic` | Upload/download totals and current speeds |
| GET | `/api/v1/inbounds` | Active inbound listeners |
| GET/POST | `/api/v1/dns/resolve` | Resolve a name through the built-in resolver |
| POST | `/api/v1/route/test` | Dry-run the router against a destination |
| GET | `/api/v1/rules` | Compiled routing rules |
| GET | `/api/v1/outbounds` | Outbound list with tags/types |
| GET | `/api/v1/outbounds/{tag}` | Outbound detail |
| GET | `/api/v1/outbounds/{tag}/delay` | Latency probe (`?url=…&timeout=ms`; private destinations refused) |
| PUT/POST | `/api/v1/outbounds/{group}/select` | Switch a Selector group's active outbound (the `/select` suffix is required) |
| GET | `/api/v1/connections` | Active connections (id, meta, counters, age) |
| DELETE | `/api/v1/connections/{id}` | Force-close one connection |
| DELETE | `/api/v1/connections` | Force-close all connections |

## Security notes

- Authentication: `Authorization: Bearer <secret>`, or `?token=<secret>`. Comparison
  is constant-time. An empty or whitespace-only `secret` is treated as **unset**.
- Cross-origin requests are rejected before any state-changing dispatch. Only
  HTTP origins whose host is exactly `localhost`, `127.0.0.1` or `::1` count as
  local — `http://localhost.attacker.tld` does not.
- Requests are bounded: 16 KiB of headers, 1 MiB of body, 15 s per connection.
- The API listener binds exclusively (no `SO_REUSEPORT`), so another process
  cannot race or hijack the port.
- `GET /api/v1/outbounds/{tag}/delay` (probe) refuses private, loopback,
  link-local and ULA destinations, and fails **closed** when a host name cannot
  be resolved.

## Prometheus

Scrape config example:

```yaml
scrape_configs:
  - job_name: flux-core
    static_configs:
      - targets: ["127.0.0.1:9090"]
    metrics_path: /api/v1/metrics
    authorization:
      credentials: "${FLUX_API_SECRET}"   # omit if no secret on loopback
```

## Examples

```bash
# Status (loopback, no secret)
curl -s http://127.0.0.1:9090/api/v1/status | jq

# Switch selector group
curl -s -X PUT http://127.0.0.1:9090/api/v1/outbounds/pick/select \
  -H "Authorization: Bearer $FLUX_API_SECRET" \
  -H 'Content-Type: application/json' -d '{"outbound":"node-b"}'

# Kill a stuck connection
curl -s -X DELETE "http://127.0.0.1:9090/api/v1/connections/$CONN_ID" \
  -H "Authorization: Bearer $FLUX_API_SECRET"
```
