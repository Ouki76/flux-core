#!/usr/bin/env python3
import asyncio
import os
import signal
import socket
import struct
import subprocess
import time
from pathlib import Path

FLUX_BIN = Path(__file__).resolve().parent.parent / "target" / "release" / "flux-core"
SINGBOX_BIN = Path(os.environ.get("SINGBOX_BIN", Path.home() / ".local" / "bin" / "sing-box"))

def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def get_process_rss(pid: int) -> float:
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    return float(line.split()[1]) / 1024.0
    except Exception:
        pass
    return 0.0

def get_process_peak_rss(pid: int) -> float:
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("VmHWM:"):
                    return float(line.split()[1]) / 1024.0
    except Exception:
        pass
    return 0.0

async def start_fast_echo_server(port: int):
    async def echo_handler(reader, writer):
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(echo_handler, "127.0.0.1", port)
    return server

async def socks5_connect(port: int, target_port: int):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    resp = await reader.readexactly(2)
    assert resp == b"\x05\x00"

    ip = socket.inet_aton("127.0.0.1")
    req = b"\x05\x01\x00\x01" + ip + struct.pack("!H", target_port)
    writer.write(req)
    await writer.drain()
    resp = await reader.readexactly(4)
    assert resp[1] == 0x00
    atyp = resp[3]
    if atyp == 0x01:
        await reader.readexactly(6)
    elif atyp == 0x03:
        dlen = (await reader.readexactly(1))[0]
        await reader.readexactly(dlen + 2)
    elif atyp == 0x04:
        await reader.readexactly(18)
    return reader, writer

async def measure_proxy(name: str, bin_cmd: list, cfg_content: str, proxy_port: int, echo_port: int, cfg_path: str):
    with open(cfg_path, "w") as f:
        f.write(cfg_content)

    proc = subprocess.Popen(
        bin_cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )

    try:
        # Wait for port open
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.1):
                    break
            except (ConnectionRefusedError, socket.timeout):
                time.sleep(0.05)

        time.sleep(0.1)
        idle_rss = get_process_rss(proc.pid)

        # 1. Latency test (100 handshakes)
        latencies = []
        for _ in range(100):
            t0 = time.perf_counter()
            r, w = await socks5_connect(proxy_port, echo_port)
            w.write(b"x")
            await w.drain()
            b = await r.readexactly(1)
            lat = (time.perf_counter() - t0) * 1000.0
            latencies.append(lat)
            w.close()
            await w.wait_closed()

        avg_lat = sum(latencies) / len(latencies)
        latencies.sort()
        p95_lat = latencies[int(len(latencies) * 0.95)]

        # 2. Throughput test (500 MB)
        total_mb = 500
        total_bytes = total_mb * 1024 * 1024
        chunk_size = 64 * 1024
        chunks = total_bytes // chunk_size
        chunk_data = b"M" * chunk_size

        r, w = await socks5_connect(proxy_port, echo_port)

        t_start = time.perf_counter()

        async def send_worker():
            for _ in range(chunks):
                w.write(chunk_data)
                await w.drain()

        async def recv_worker():
            received = 0
            while received < total_bytes:
                data = await r.read(chunk_size)
                if not data:
                    break
                received += len(data)
            return received

        _, rec_total = await asyncio.gather(send_worker(), recv_worker())
        t_elapsed = time.perf_counter() - t_start
        w.close()
        await w.wait_closed()

        speed_mb_s = (rec_total / 1024.0 / 1024.0) / t_elapsed
        speed_gbps = (rec_total * 8.0 / 1e9) / t_elapsed

        time.sleep(0.1)
        peak_rss = get_process_peak_rss(proc.pid)
        current_rss = get_process_rss(proc.pid)

        return {
            "name": name,
            "idle_rss": idle_rss,
            "peak_rss": peak_rss,
            "current_rss": current_rss,
            "speed_mb_s": speed_mb_s,
            "speed_gbps": speed_gbps,
            "avg_lat": avg_lat,
            "p95_lat": p95_lat,
        }
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass

async def main():
    echo_port = get_free_port()
    echo_server = await start_fast_echo_server(echo_port)

    flux_port = get_free_port()
    singbox_port = get_free_port()

    flux_cfg = f"""{{
  "inbounds": [{{
    "tag": "socks-in",
    "carrier": {{ "type": "tcp", "listen": "127.0.0.1", "listen_port": {flux_port} }},
    "protocol": {{ "type": "socks" }}
  }}],
  "outbounds": [{{
    "type": "direct",
    "tag": "direct"
  }}]
}}"""

    singbox_cfg = f"""{{
  "inbounds": [{{
    "type": "socks",
    "tag": "socks-in",
    "listen": "127.0.0.1",
    "listen_port": {singbox_port}
  }}],
  "outbounds": [{{
    "type": "direct",
    "tag": "direct"
  }}]
}}"""

    print("Running Head-to-Head Benchmark: flux-core vs sing-box 1.11.4 ...")
    flux_res = await measure_proxy(
        "flux-core (Rust 2024)",
        [str(FLUX_BIN), "run", "-c", "/tmp/bench_flux.json", "-f", "json"],
        flux_cfg,
        flux_port,
        echo_port,
        "/tmp/bench_flux.json"
    )

    singbox_res = await measure_proxy(
        "sing-box (Go 1.24)",
        [str(SINGBOX_BIN), "run", "-c", "/tmp/bench_singbox.json"],
        singbox_cfg,
        singbox_port,
        echo_port,
        "/tmp/bench_singbox.json"
    )

    flux_bin_size = FLUX_BIN.stat().st_size / (1024 * 1024)
    sing_bin_size = SINGBOX_BIN.stat().st_size / (1024 * 1024)

    print("\n" + "=" * 80)
    print("HEAD-TO-HEAD BENCHMARK RESULTS (500 MB Stream Transfer)")
    print("=" * 80)
    print(f"{'Metric':<34} | {'flux-core':<18} | {'sing-box':<18} | {'Advantage'}")
    print("-" * 80)
    print(f"{'Binary Size':<34} | {flux_bin_size:.2f} MB{'':<11} | {sing_bin_size:.2f} MB{'':<11} | \033[1;32m{sing_bin_size/flux_bin_size:.1f}x smaller\033[0m")
    print(f"{'Idle Memory (VmRSS)':<34} | {flux_res['idle_rss']:.2f} MB{'':<11} | {singbox_res['idle_rss']:.2f} MB{'':<11} | \033[1;32m{singbox_res['idle_rss']/max(0.1, flux_res['idle_rss']):.1f}x less RAM\033[0m")
    print(f"{'Peak Memory (under 500MB stream)':<34} | {flux_res['peak_rss']:.2f} MB{'':<11} | {singbox_res['peak_rss']:.2f} MB{'':<11} | \033[1;32m{singbox_res['peak_rss']/max(0.1, flux_res['peak_rss']):.1f}x less RAM\033[0m")
    print(f"{'Post-Stream RSS (Leak check)':<34} | {flux_res['current_rss']:.2f} MB{'':<11} | {singbox_res['current_rss']:.2f} MB{'':<11} | \033[1;32m{singbox_res['current_rss']/max(0.1, flux_res['current_rss']):.1f}x less RAM\033[0m")
    print(f"{'Throughput (MB/s)':<34} | {flux_res['speed_mb_s']:.1f} MB/s{'':<9} | {singbox_res['speed_mb_s']:.1f} MB/s{'':<9} | \033[1;32m{flux_res['speed_mb_s']/singbox_res['speed_mb_s']:.2f}x speed\033[0m")
    print(f"{'Throughput (Gbps)':<34} | {flux_res['speed_gbps']:.2f} Gbps{'':<9} | {singbox_res['speed_gbps']:.2f} Gbps{'':<9} | \033[1;32m{flux_res['speed_gbps']/singbox_res['speed_gbps']:.2f}x bandwidth\033[0m")
    print(f"{'Avg Handshake Latency':<34} | {flux_res['avg_lat']:.2f} ms{'':<11} | {singbox_res['avg_lat']:.2f} ms{'':<11} | \033[1;32m{singbox_res['avg_lat']/flux_res['avg_lat']:.2f}x faster\033[0m")
    print(f"{'p95 Handshake Latency':<34} | {flux_res['p95_lat']:.2f} ms{'':<11} | {singbox_res['p95_lat']:.2f} ms{'':<11} | \033[1;32m{singbox_res['p95_lat']/flux_res['p95_lat']:.2f}x faster\033[0m")
    print("=" * 80 + "\n")

    echo_server.close()
    await echo_server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
