# Deployment Runbook

## Artifacts

- **Static-ish Linux binary**: `cargo build --release` → `target/release/flux-core` (~9.4 MB, stripped, `lto=fat`, `codegen-units=1`).
- **Container image**: multi-stage `Dockerfile` (Debian slim runtime with `ca-certificates`, `iptables`, `iproute2`).

## System requirements

- Linux x86_64 (primary target; zero-copy `splice(2)`, TUN, REDIRECT, TPROXY are Linux-specific).
- Kernel ≥ 4.x for `splice`/`SO_ORIGINAL_DST`; `/dev/net/tun` for the TUN inbound.
- RAM: measured idle footprint 7.5 MB (16 worker threads); **~4 KB of RSS per
  established TCP relay** (500 held loopback connections → +1.9 MB total). The
  kernel-side `splice(2)` pipes are allocated lazily, so idle pipes cost ~0.
- File descriptors: **6 per relayed TCP connection** (2 sockets + 4 pipe ends for
  the two `splice` directions). Raise `LimitNOFILE` accordingly — the example
  systemd unit uses 1048576, good for ~170k concurrent relays.

## Capabilities

| Feature | Required privilege |
|---|---|
| TCP/UDP listeners on ports ≥ 1024 | none |
| Ports < 1024 | `CAP_NET_BIND_SERVICE` |
| TUN inbound | `CAP_NET_ADMIN` + `/dev/net/tun` |
| TPROXY inbound | `CAP_NET_ADMIN` (+ iptables/nftables rules) |
| REDIRECT inbound | `CAP_NET_ADMIN` |

Container:

```bash
docker build -t flux-core .
# Plain listeners only:
docker run -d -v $PWD/config.yaml:/etc/flux-core/config.json flux-core
# Transparent proxying:
docker run -d --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE \
  --device /dev/net/tun -v $PWD/config.yaml:/etc/flux-core/config.json flux-core
```

> **SELinux hosts (Fedora/RHEL/CentOS):** append `:Z` to volume mounts,
> otherwise the container cannot read the config (`Permission denied`):
> `-v $PWD/config.yaml:/etc/flux-core/config.json:Z`

The image ships a `HEALTHCHECK` running `flux-core check -c /etc/flux-core/config.json`.

## systemd

```ini
[Unit]
Description=flux-core proxy
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/flux-core run -c /etc/flux-core/config.yaml
ExecReload=/bin/kill -HUP $MAINPID   # config reload (see below)
Restart=on-failure
RestartSec=2
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

## Pre-flight checklist

1. `flux-core check -c config.yaml` — config valid.
2. Secrets come from environment (`${VAR}` expansion), never committed.
3. Management API is loopback-only **or** has `secret` set (the process refuses a public listener without one unless `allow_insecure_api: true`).
4. Public inbounds have `rate_limit` configured.
5. `LimitNOFILE` raised for high connection counts.
6. Log level `info` (or `warn`) in production; `debug`/`trace` for diagnosis only.

## Monitoring

- **Prometheus**: `GET /api/v1/metrics` (see [api.md](api.md)).
- **Health**: `GET /api/v1/status`; container `HEALTHCHECK` included.
- **Logs**: structured `tracing` output on stdout (journald/Docker capture).

## Upgrades / rollback

1. `flux-core check -c new-config.yaml` on the new artifact/config.
2. Rolling or blue/green restart; the binary is a single static file, rollback = previous binary + config.
3. Remote rule sets are failure-safe: a bad fetch never breaks routing (last good matcher stays active, disk cache applied at startup).

## Load & soak validation

```bash
scripts/soak.sh 86400     # 24h sustained load with RSS/FD/thread sampling and leak assertion
```

Run a full 24h soak in staging before the first production rollout of a new build.
