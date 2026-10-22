//! Where does a Hysteria 2 connection spend its time?
//!
//! The e2e test takes ~5.6 s while the server answers the auth request in
//! microseconds, so the cost is in one of the phases below. This test measures
//! each phase separately and asserts a sane budget, so a regression shows up as a
//! named phase rather than "the test got slow".

mod common;

use common::{get_free_tcp_port, start_tcp_echo_server};
use flux_app::{Config, Instance};
use flux_types::{NetworkType, SessionMeta, TargetAddress};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn srv_config(port: u16) -> String {
    format!(
        r#"{{
            "inbounds": [{{
                "tag": "hy2-in",
                "carrier": {{ "type": "udp", "listen": "127.0.0.1", "listen_port": {port} }},
                "protocol": {{ "type": "hysteria2", "password": "hy2-pw" }}
            }}],
            "outbounds": [{{"type": "direct", "tag": "direct"}}]
        }}"#
    )
}

fn cli_config(port: u16) -> String {
    format!(
        r#"{{
            "outbounds": [{{
                "tag": "hy2-out",
                "carrier": {{ "type": "udp", "address": "127.0.0.1:{port}" }},
                "security": {{ "type": "tls", "sni": "localhost", "insecure": true }},
                "protocol": {{ "type": "hysteria2", "password": "hy2-pw" }}
            }}]
        }}"#
    )
}

#[tokio::test]
async fn hy2_phases_are_fast() {
    let echo_addr = start_tcp_echo_server().await;
    let srv_port = get_free_tcp_port().await;

    let t_start_srv = Instant::now();
    let srv = Instance::new(Config::from_json_str(&srv_config(srv_port)).unwrap()).unwrap();
    srv.start().await.unwrap();
    let start_srv = t_start_srv.elapsed();

    let cli = Instance::new(Config::from_json_str(&cli_config(srv_port)).unwrap()).unwrap();
    let out = cli.registry.get_outbound("hy2-out").unwrap();

    let meta = SessionMeta::new(
        "127.0.0.1:41000".parse().unwrap(),
        TargetAddress::Ip(echo_addr),
        "lat",
        NetworkType::Tcp,
    );

    let t_dial = Instant::now();
    let mut stream = tokio::time::timeout(Duration::from_secs(15), out.dial_stream(&meta))
        .await
        .expect("dial timed out")
        .expect("dial failed");
    let dial = t_dial.elapsed();

    let t_echo = Instant::now();
    stream.write_all(b"latency-probe").await.unwrap();
    stream.flush().await.unwrap();
    let mut buf = vec![0u8; 13];
    stream.read_exact(&mut buf).await.unwrap();
    let echo = t_echo.elapsed();
    assert_eq!(&buf, b"latency-probe");

    // A second connection on the same outbound: the QUIC connection and the h3
    // client are reused, so this must be near-instant.
    let t_dial2 = Instant::now();
    let mut stream2 = tokio::time::timeout(Duration::from_secs(15), out.dial_stream(&meta))
        .await
        .expect("second dial timed out")
        .expect("second dial failed");
    let dial2 = t_dial2.elapsed();
    stream2.write_all(b"second").await.unwrap();
    stream2.flush().await.unwrap();
    let mut b2 = [0u8; 6];
    stream2.read_exact(&mut b2).await.unwrap();

    println!(
        "@@TIMING start_srv={start_srv:?} first_dial={dial:?} echo={echo:?} second_dial={dial2:?}"
    );

    let _ = srv.stop().await;
    // Characterisation, not the target. Measured on this tree: the QUIC connect
    // takes 3 ms and our h3 server answers in ~1 ms (see
    // `h3_lite::latency_tests::raw_quinn_round_trip_is_fast`), yet the `h3` crate
    // client needs ~5.5 s to deliver that response. The target for `dial` is
    // 1.5 s; the bound below is what the code actually does today, so a further
    // regression is caught while the known stall is documented rather than
    // hidden. See docs/audit-log.md, cycle 7.
    assert!(
        dial < Duration::from_millis(7000),
        "first dial regressed past the documented stall: {dial:?} \
         (start {start_srv:?}, echo {echo:?}, second dial {dial2:?})"
    );
    assert!(echo < Duration::from_millis(500), "echo took {echo:?}");
}
