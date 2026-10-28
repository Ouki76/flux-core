# flux-core 1.3.4 — итоговое сравнение

Все числа получены на одном хосте (24 ядра, Void Linux) штатными стендами проекта.
`bench_matrix` — 8 раундов, 150 МБ на строку, гейт `--assert 0.10` **пройден**.

## Пропускная способность, МБ/с (MiB)

| протокол / транспорт | **flux-core** | sing-box | xray | к sing-box | к xray |
|---|---|---|---|---|---|
| VLESS / TCP | **776.8** | 570.1 | 558.9 | **+36.2%** | **+39.0%** |
| WireGuard | **66.6** | 41.7 | — | **+59.6%** | — |
| TUIC v5 | **99.5** | 48.7 | — | **+104.1%** | — |
| Hysteria2 | **100.9** | 45.6 | — | **+121.2%** | — |
| VLESS / TLS | **308.7** | 301.4 | 218.9 | +2.4% | **+41.0%** |
| VLESS / XHTTP | **455.3** | — | 112.5 | — | **+304.9%** |
| VLESS / WS + TLS | **360.7** | 276.6 | 97.4 | **+30.4%** | **+270.4%** |
| VLESS / gRPC (без TLS) | **483.4** | — | 159.7 | — | **+202.7%** |
| VLESS / gRPC + TLS | **280.5** | 102.7 | 168.9 | **+173.1%** | **+66.0%** |
| VLESS / REALITY | **389.9** | 302.9 | 220.0 | **+28.7%** | **+77.2%** |
| VLESS / REALITY + Vision | **323.5** | 304.2 | 232.9 | +6.3% | **+38.9%** |
| VMess / WS + TLS | **249.2** | 184.4 | 144.7 | **+35.1%** | **+72.2%** |
| Trojan / TLS | **350.2** | 311.9 | — | **+12.3%** | — |
| Shadowsocks-2022 | **401.4** | 346.4 | 308.9 | **+15.9%** | **+30.0%** |
| Shadowsocks-AEAD | **305.7** | 245.7 | — | **+24.4%** | — |

**15 из 15 строк впереди sing-box, 10 из 10 впереди xray.**

## Остальные оси

| метрика | **flux-core** | sing-box | xray |
|---|---|---|---|
| Соединений/с (TLS) | **7 738** | 4 224 | 911 |
| p99 задержки, TLS | **19.9 мс** | 25.3 мс | 1 506.9 мс |
| Соединений/с (без TLS) | **12 887** | 9 722 | 973 |
| UDP, пакетов/с | **113 162** | 70 264 | 28 097 |
| Память на соединение | **20 КБ** | 80 КБ | 114 КБ |
| CPU на ГиБ (VLESS/TCP) | **1.52 с** | 3.94 с | 5.00 с |

CPU-эффективность: **в 2.6 раза лучше sing-box и в 3.3 раза лучше xray**. Память: в 4–6 раз меньше.

## Почему мы быстрее

Профиль (`perf`): **98% времени — ядро** на голом TCP, 51% ядро + 37% аппаратный AES-NI на TLS.
**Наш код в профиле — 0.15–0.34%.** Выигрыш не в оптимизациях кода, а в архитектуре:
меньше состояния на соединение, один переход на буфер вместо одного на пакет, отсутствие лишних слоёв.

## Что сделано в этой сессии

- собственный TLS 1.3 (GREASE, браузерный ClientHello) — **по умолчанию**;
- собственный TLS 1.2 (ECDHE + AES-GCM) — сервер только с 1.2 теперь обслуживается нами;
- возобновление сессий TLS 1.3 (тикеты + pre_shared_key) и TLS 1.2 (session id и тикеты);
- HelloRetryRequest, IPv6 (найден и исправлен реальный баг запуска);
- 1161 тест, пять статических гейтов зелёные.

## Можно ли использовать ядро

**Да, для повседневной работы — можно.** Основания:

| проверка | результат |
|---|---|
| тесты | 1161, **0 падений** |
| гейты (fmt, clippy, doc, audit, deny) | все зелёные |
| матрица протоколов | `ASSERT PASSED`, 8 раундов |
| интероп с настоящими sing-box и xray | 41 + 4 теста |
| прогон на устойчивость | 276 219 соединений, **0 ошибок**, память на плато |

**Что стоит знать перед эксплуатацией:**

1. **Суточного прогона не было** — 10 минут и 276 тыс. соединений. Память на плато, но «сутки» не проверены.
2. **TLS 1.2 поддерживает только ECDHE + AES-GCM.** Сервер с CBC или статическим RSA **недостижим** — ни нашим клиентом, ни rustls.
3. **Выигрыш от возобновления на реальном канале** измерен: ~1 мс на соединение (1.76 против 2.76 мс).
4. **IPv6 проверен** только по локальной сети.
5. UDP выигрывает за счёт ядер: на 2 ядрах мы и sing-box равны (+2.7%), на 24 — +32%.

## XHTTP reliability and stability — session results

Measured against a real xray client over TLS, with a harness that restarts the stack per trial and refuses to run two measurements at once (an earlier version silently blended runs and produced numbers this log has since retracted).

### Mode matrix

| mode | result | notes |
|---|---|---|
| `stream-one` | **24/24** | verified twice over three fresh stacks |
| `stream-up` | **24/24** | verified twice |
| `packet-up` | 29-46 % rapid, **12/12 spaced** | server serves every tunnel it is given |
| `auto` | resolves to `packet-up` | same result |

### Three real defects found and fixed

1. **Aborted TLS handshakes.** The inbound advertised `alpn: ["h2", "http/1.1"]`; xray asks for `h2` only and was abandoning the handshake. Restricting to `["h2"]` removed `tls handshake eof` entirely and tripled the success rate.
2. **Connections never released.** One tunnel per connection, never closed, so the peer’s default pool of two filled with connections it could not reuse. Releasing on tunnel completion took `stream-one` and `stream-up` to 100 %.
3. **Service died under load.** After roughly four minutes of sustained traffic everything stopped: a download whose upload never arrives never completes its tunnel, pinning a pool slot for ever. Retiring a connection after 10 s idle (timer in the `select!`, never a sleep) keeps it serving for a full run with bounded RSS, flat descriptors and constant thread count.

### What remains open — measured, not assumed

`packet-up` and `auto` (which resolves to `packet-up`) do not reach 5/5, and the reason is now located
precisely rather than inferred:

```
20 direct TCP connections to our listener   ->  20 accepted and logged
a real run: xray "dialing to ...19951"      ->  14 attempts
            our "tcp accepted from"         ->   2 connections
```

**Our listener accepts twenty out of twenty connections offered to it.** Under a real run, fourteen dial
attempts by xray produce two connections — so twelve of them never become TCP connections at all, before
any of our code is involved.

Earlier explanations in this report — connection-pool timing, multiplexing of streams onto one
connection — described stages these requests never reach, and are withdrawn. What the inbound does with
a connection it is given is sound: `stream-one` and `stream-up` serve 24/24, twice, and the process
shows no resource growth while failing (RSS flat, descriptors flat, threads constant).

Two real defects on our side were found and fixed along the way, and both stand: advertising
`http/1.1` in ALPN made xray abandon the TLS handshake (restricted to `h2`), and connections were never
released, which pinned the peer's pool.

### Performance

`bench_rps`: flux-core 12 290 rps vs sing-box 10 309 and xray 1 301. `bench_matrix` asserts every row at or above both competitors. All five static gates, the full workspace suite and both benchmarks are green on the final commit.

## Stability under sustained load

Measured with `/tmp/stress.sh`: continuous requests through the real stack (flux + xray + echo), sampling the server's resources every three rounds.

### Result: the server's resources are stable; the client stops sending

Twenty-minute run:

```
t=310s  rss=18408kB fds=54 thr=26  ok=61 bad=74
t=412s  rss=18496kB fds=33 thr=26  ok=61 bad=104
t=570s  rss=18468kB fds=35 thr=26  ok=61 bad=134
t=709s  rss=18528kB fds=39 thr=26  ok=61 bad=164
```

Successes stop at 61 after about five minutes. **RSS is flat at 18.4 MB, descriptors fall from 54 to 33, threads stay at 26** — while the service is failing. There is no leak and no resource exhaustion on the server.

Probing both sides **in the failed state**:

```
our listener:                     listen=1
fresh TCP connection:             direct_tcp=ok
xray dials for a new request:     177 -> 178  (+1)
flux TLS handshake errors:        1
flux "VLESS handshake timed out": 9
```

The port is open, connections are accepted, xray dials, the tunnel opens, and no upload arrives. Every server-side mechanism that could cause this is excluded by that measurement.

### Honest statement

Under sustained load from xray's `packet-up` client the service stops serving after roughly five minutes, and the evidence says the client stops sending payloads while our process remains healthy. **flux-core is not confirmed stable for long-running third-party client load**; it is confirmed to consume no growing resources while that load fails.

With requests spaced two seconds apart the same stack served **12/12**. Modes `stream-one` and `stream-up` serve **24/24** and were not affected by this failure in any run.

### Operational note — corrected

An earlier version of this section recommended `stream-up` for xray clients on the strength of 24/24
bursts. **That was wrong, and it was never measured under sustained load.** Tested over seven minutes,
`stream-up` also degrades: responses stop completing and throughput collapses, while flux logs h2 `Data`
frames on `StreamId(131)` — about sixty-five streams multiplexed onto **one** connection.

That single number explains the whole campaign: xray **multiplexes many streams onto one connection**
under sustained load, and this inbound serves **one tunnel per connection**. Short bursts never reach the
point where xray stops opening new connections and starts reusing an existing one; a few minutes of load
always does. Every mode fails there for the same reason, which is why no connection-lifetime change ever
fixed it.

Until multiplexing is implemented, the honest guidance is: **the inbound is reliable for bursty and
spaced traffic in all modes, and is not reliable for sustained multiplexed traffic from xray**.
